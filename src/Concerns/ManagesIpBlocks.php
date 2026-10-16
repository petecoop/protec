<?php

declare(strict_types=1);

namespace Petecoop\Protec\Concerns;

use Illuminate\Support\Facades\RateLimiter;
use InvalidArgumentException;
use Petecoop\Protec\Data\Detection;
use Petecoop\Protec\Duration;
use Petecoop\Protec\Events\IpBlocked;
use Petecoop\Protec\Events\IpUnblocked;
use Petecoop\Protec\Models\IpBlock;

trait ManagesIpBlocks
{
    /** @param array<string, mixed> $context */
    public function ban(
        string $ip,
        int|string|null $for = null,
        string $reason = 'manual',
        array $context = [],
    ): IpBlock {
        $ip = $this->normalizeIp($ip);
        $seconds = $for === null ? null : Duration::seconds($for);

        if ($ip === null || $seconds !== null && $seconds < 1) {
            throw new InvalidArgumentException('A ban requires a valid IP and a positive duration or null.');
        }

        return $this->blockIp($ip, 'manual', new Detection($reason, $context), $seconds);
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

    protected function newBlockModel(): IpBlock
    {
        return new (config('protec.model', IpBlock::class));
    }

    protected function findActiveBlock(string $ip): ?IpBlock
    {
        return $this->newBlockModel()->newQuery()->active()->where('ip_address', $ip)->first();
    }

    protected function blockIp(
        string $ip,
        string $detector,
        Detection $detection,
        ?int $seconds,
    ): IpBlock {
        $model = $this->newBlockModel();
        $changed = false;

        $block = $model
            ->getConnection()
            ->transaction(function () use ($model, $ip, $detector, $detection, $seconds, &$changed): IpBlock {
                $attributes = $this->blockAttributes($detector, $detection, $seconds);
                $block = $model->newQuery()->firstOrCreate(['ip_address' => $ip], $attributes);
                $block = $block->wasRecentlyCreated
                    ? $block
                    : $model->newQuery()->whereKey($block->getKey())->lockForUpdate()->firstOrFail();

                if ($block->wasRecentlyCreated || $detector === 'manual' || ! $block->isActive()) {
                    $attributes = $detector === 'manual' ? $attributes : $this->escalateBlock($block, $attributes);
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
    protected function blockAttributes(string $detector, Detection $detection, ?int $seconds): array
    {
        return [
            'detector' => $detector,
            'reason' => $detection->reason,
            'context' => $detection->context,
            'expires_at' => $seconds === null ? null : now()->addSeconds($seconds),
        ];
    }

    /** @param array<string, mixed> $attributes
     * @return array<string, mixed>
     */
    protected function escalateBlock(IpBlock $block, array $attributes): array
    {
        return $this->detectors()->escalation($attributes['detector'])?->apply($block, $attributes) ?? $attributes;
    }
}
