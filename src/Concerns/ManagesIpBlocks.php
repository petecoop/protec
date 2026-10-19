<?php

declare(strict_types=1);

namespace Petecoop\Protec\Concerns;

use Closure;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\RateLimiter;
use InvalidArgumentException;
use Petecoop\Protec\Data\Detection;
use Petecoop\Protec\Data\IpSummary;
use Petecoop\Protec\Duration;
use Petecoop\Protec\Events\IpBlocked;
use Petecoop\Protec\Events\IpUnblocked;
use Petecoop\Protec\Models\IpBlock;

trait ManagesIpBlocks
{
    public function ip(string $ip): IpSummary
    {
        $ip = $this->normalizeIp($ip) ?? throw new InvalidArgumentException(
            'An IP summary requires a valid IP address.',
        );
        $query = $this->newBlockModel()->newQuery()->where('ip_address', $ip);
        $active = (clone $query)->active()->get();
        $permanent = $active->contains(static fn (IpBlock $block): bool => $block->expires_at === null);

        return new IpSummary(
            ipAddress: $ip,
            totalBlocks: (clone $query)->count(),
            activeBlocks: $active->count(),
            blockedUntil: $permanent ? null : $active->max('expires_at'),
            latestBlock: $query->latest('id')->first(),
        );
    }

    /** @param array<string, mixed> $context */
    public function block(
        string $ip,
        int|string|null $for = null,
        ?string $reason = null,
        array $context = [],
    ): IpBlock {
        $ip = $this->normalizeIp($ip);
        $seconds = $for === null ? null : Duration::seconds($for);

        if ($ip === null || $seconds !== null && $seconds < 1) {
            throw new InvalidArgumentException('A block requires a valid IP and a positive duration or null.');
        }

        return $this->blockIp($ip, null, new Detection($reason, $context), $seconds);
    }

    public function unblock(string $ip): bool
    {
        $ip = $this->normalizeIp($ip);

        if ($ip === null) {
            return false;
        }

        $blocks = $this->withIpLock($ip, function () use ($ip) {
            $model = $this->newBlockModel();

            $blocks = $model
                ->getConnection()
                ->transaction(function () use ($model, $ip) {
                    $blocks = $model->newQuery()->active()->where('ip_address', $ip)->get();
                    $unblockedAt = now();

                    foreach ($blocks as $block) {
                        $block->forceFill(['unblocked_at' => $unblockedAt])->save();
                        RateLimiter::clear($this->rateLimitKey($ip, $block->detector, $block->reason));
                    }

                    return $blocks;
                });

            $this->refreshBlockCache($ip);

            return $blocks;
        });

        foreach ($blocks as $block) {
            event(new IpUnblocked($block));
        }

        return $blocks->isNotEmpty();
    }

    protected function newBlockModel(): IpBlock
    {
        return new (config('protec.model', IpBlock::class));
    }

    protected function findActiveBlock(string $ip): ?IpBlock
    {
        return $this
            ->newBlockModel()
            ->newQuery()
            ->active()
            ->where('ip_address', $ip)
            ->latest('id')
            ->first();
    }

    protected function blockIp(
        string $ip,
        ?string $detector,
        Detection $detection,
        ?int $seconds,
    ): IpBlock {
        $created = false;
        $block = $this->withIpLock($ip, function () use ($ip, $detector, $detection, $seconds, &$created): IpBlock {
            $model = $this->newBlockModel();

            $block = $model
                ->getConnection()
                ->transaction(function () use ($model, $ip, $detector, $detection, $seconds, &$created): IpBlock {
                    $activeBlock = $detector === null ? null : $this->findActiveBlock($ip);

                    if ($activeBlock !== null) {
                        return $activeBlock;
                    }

                    $block = $model->newInstance(['ip_address' => $ip]);
                    $attributes = $this->blockAttributes($detector, $detection, $seconds);
                    $attributes = $detector === null ? $attributes : $this->escalateBlock($block, $attributes);
                    $block->forceFill($attributes)->save();
                    $created = true;

                    return $block;
                });

            $this->refreshBlockCache($ip);

            return $block;
        });

        if ($created) {
            event(new IpBlocked($block));
        }

        return $block;
    }

    /** @return array<string, mixed> */
    protected function blockAttributes(?string $detector, Detection $detection, ?int $seconds): array
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

    protected function withIpLock(string $ip, Closure $callback): mixed
    {
        // Coordinate even the first block, when there is no database row to lock.
        return Cache::store(config('cache.limiter'))
            ->lock('protec:ip:'.hash('sha256', $ip), 30)
            ->block(5, $callback);
    }
}
