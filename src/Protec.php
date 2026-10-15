<?php

declare(strict_types=1);

namespace Petecoop\Protec;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use InvalidArgumentException;
use Petecoop\Protec\Contracts\Exemption;
use Petecoop\Protec\Data\Detection;
use Petecoop\Protec\Data\Inspection;
use Petecoop\Protec\Data\Limit;
use Petecoop\Protec\Detectors\CorruptLivewirePayload;
use Petecoop\Protec\Events\ActivityDetected;
use Petecoop\Protec\Events\IpBlocked;
use Petecoop\Protec\Events\IpUnblocked;
use Petecoop\Protec\Models\IpBlock;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

// The service deliberately exposes behaviour as subclass hooks on one container binding.
// @mago-expect lint:cyclomatic-complexity
// @mago-expect lint:kan-defect
// @mago-expect lint:too-many-methods
class Protec
{
    public function shouldInspect(Request $request): bool
    {
        if (! config('protec.enabled', default: true)) {
            return false;
        }

        foreach (config('protec.exemptions', []) as $class) {
            $exemption = app($class);

            if (! $exemption instanceof Exemption) {
                throw new InvalidArgumentException("Protec exemption [{$class}] must implement Exemption.");
            }

            if ($exemption->applies($request)) {
                return false;
            }
        }

        return true;
    }

    public function blocked(Request $request): ?IpBlock
    {
        if (! $this->shouldInspect($request)) {
            return null;
        }

        $ip = $this->resolveIp($request);

        return $ip === null ? null : $this->findActiveBlock($ip);
    }

    public function inspect(Inspection $inspection): ?Response
    {
        if (! $this->shouldInspect($inspection->request)) {
            return null;
        }

        $block = $this->blocked($inspection->request);

        if ($block !== null) {
            return $this->respond($inspection->request, $block);
        }

        foreach ($this->detectors()->definitions() as $class => $definition) {
            $detection = $this->detectors()->detector($class)->detect($inspection);

            if ($detection === null) {
                continue;
            }

            $limit = $this->detectors()->policy($definition)->evaluate($detection, $inspection->request);
            $response = $this->enforce($inspection->request, $detection, $limit, $class);

            if ($response !== null) {
                return $response;
            }
        }

        return null;
    }

    public function record(
        Request $request,
        Detection $detection,
        Limit $limit = new Limit,
        string $detector = 'application',
    ): ?IpBlock {
        if (! $this->shouldInspect($request)) {
            return null;
        }

        $ip = $this->resolveIp($request);

        if ($ip === null) {
            return null;
        }

        return $this->findActiveBlock($ip) ?? $this->recordActivity($ip, $detector, $detection, $limit);
    }

    public function respond(Request $request, ?IpBlock $block = null, int $status = 429): Response
    {
        return response('', $status);
    }

    public function unblock(string $ip): bool
    {
        $ip = $this->normalizeIp($ip);

        if ($ip === null) {
            return false;
        }

        $block = $this->newBlockModel()->newQuery()->where('ip_address', $ip)->first();

        if ($block === null || ! $block->isActive()) {
            return false;
        }

        $block->forceFill(['expires_at' => now()])->save();
        RateLimiter::clear($this->rateLimitKey($ip, $block->detector, $block->reason));
        event(new IpUnblocked($block));

        return true;
    }

    public function isLivewireTampering(Inspection $inspection): bool
    {
        if (! $this->shouldInspect($inspection->request)) {
            return false;
        }

        foreach ($this->detectors()->definitions() as $class => $definition) {
            $detector = $this->detectors()->detector($class);

            if ($detector instanceof CorruptLivewirePayload && $detector->detect($inspection) !== null) {
                return true;
            }
        }

        return false;
    }

    public function handleException(Response $response, Throwable $exception, Request $request): Response
    {
        return $this->inspect(new Inspection($request, $response, $exception)) ?? $response;
    }

    public function shouldIgnoreException(Throwable $exception, Request $request): bool
    {
        return (
            ! config('protec.report_livewire_tampering', default: false)
            && $this->isLivewireTampering(new Inspection($request, exception: $exception))
        );
    }

    protected function detectors(): DetectorRegistry
    {
        return app(DetectorRegistry::class);
    }

    protected function resolveIp(Request $request): ?string
    {
        // Laravel determines the client using its configured trusted proxies.
        // Never read forwarded headers independently of that trust boundary.
        return $this->normalizeIp($request->ip());
    }

    protected function normalizeIp(?string $ip): ?string
    {
        if ($ip === null || filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return null;
        }

        return inet_ntop(inet_pton($ip));
    }

    protected function newBlockModel(): IpBlock
    {
        return new (config('protec.model', IpBlock::class));
    }

    protected function findActiveBlock(string $ip): ?IpBlock
    {
        return $this->newBlockModel()->newQuery()->active()->where('ip_address', $ip)->first();
    }

    protected function enforce(Request $request, Detection $detection, Limit $limit, string $detector): ?Response
    {
        $block = $this->record($request, $detection, $limit, $detector);

        if ($block !== null) {
            return $this->respond($request, $block);
        }

        return $limit->rejectWith === null ? null : $this->respond($request, status: $limit->rejectWith);
    }

    protected function recordActivity(string $ip, string $detector, Detection $detection, Limit $limit): ?IpBlock
    {
        $key = $this->rateLimitKey($ip, $detector, $detection->reason);
        $attempts = RateLimiter::hit($key, $limit->within);
        event(new ActivityDetected($ip, $detector, $detection, $attempts));

        if ($attempts < $limit->attempts) {
            return null;
        }

        $block = $this->blockIp($ip, $detector, $detection, $limit->blockFor);
        RateLimiter::clear($key);

        return $block;
    }

    protected function rateLimitKey(string $ip, string $detector, string $reason): string
    {
        return 'protec:attempts:'.hash('sha256', json_encode([$ip, $detector, $reason], JSON_THROW_ON_ERROR));
    }

    protected function blockIp(string $ip, string $detector, Detection $detection, int $seconds): IpBlock
    {
        $model = $this->newBlockModel();
        $changed = false;

        $block = $model
            ->getConnection()
            ->transaction(function () use ($model, $ip, $detector, $detection, $seconds, &$changed): IpBlock {
                $attributes = $this->blockAttributes($detector, $detection, $seconds);
                $block = $model->newQuery()->firstOrCreate(['ip_address' => $ip], $attributes);

                if ($block->wasRecentlyCreated) {
                    $changed = true;

                    return $block;
                }

                $block = $model->newQuery()->whereKey($block->getKey())->lockForUpdate()->firstOrFail();

                if (! $block->isActive()) {
                    $block->forceFill($attributes)->save();
                    $changed = true;
                }

                return $block;
            });

        if ($changed) {
            event(new IpBlocked($block));
        }

        return $block;
    }

    /** @return array<string, mixed> */
    protected function blockAttributes(string $detector, Detection $detection, int $seconds): array
    {
        return [
            'detector' => $detector,
            'reason' => $detection->reason,
            'context' => $detection->context,
            'expires_at' => now()->addSeconds($seconds),
        ];
    }
}
