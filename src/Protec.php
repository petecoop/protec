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
use Petecoop\Protec\Events\ActivityDetected;
use Petecoop\Protec\Models\IpBlock;
use Symfony\Component\HttpFoundation\Response;

class Protec
{
    use Concerns\CachesIpBlocks;
    use Concerns\HandlesLivewireExceptions;
    use Concerns\IdentifiesClients;
    use Concerns\ManagesIpBlocks;

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

        return $ip === null ? null : $this->cachedActiveBlock($ip);
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

            $limit = $this->limitFor($inspection->request, $detection, $definition['policy'] ?? []);
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

        return $this->cachedActiveBlock($ip) ?? $this->recordActivity($ip, $detector, $detection, $limit);
    }

    public function respond(Request $request, ?IpBlock $block = null, int $status = 429): Response
    {
        return response('', $status);
    }

    protected function detectors(): DetectorRegistry
    {
        return app(DetectorRegistry::class);
    }

    /** @param array<string, mixed> $policy */
    protected function limitFor(Request $request, Detection $detection, array $policy): Limit
    {
        return Limit::fromConfig($policy);
    }

    protected function enforce(Request $request, Detection $detection, Limit $limit, string $detector): ?Response
    {
        $block = $this->record($request, $detection, $limit, $detector);

        if ($block !== null) {
            return $this->respond($request, $block);
        }

        $status = $limit->rejectWith ?? $detection->rejectWith;

        return $status === null ? null : $this->respond($request, status: $status);
    }

    protected function recordActivity(string $ip, string $detector, Detection $detection, Limit $limit): ?IpBlock
    {
        $detector = $this->detectors()->name($detector);
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

    protected function rateLimitKey(string $ip, ?string $detector, ?string $reason): string
    {
        return 'protec:attempts:'.hash('sha256', json_encode([$ip, $detector, $reason], JSON_THROW_ON_ERROR));
    }
}
