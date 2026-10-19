<?php

declare(strict_types=1);

namespace Petecoop\Protec\Concerns;

use Illuminate\Cache\DatabaseStore;
use Illuminate\Cache\Repository;
use Illuminate\Support\Facades\Cache;
use Petecoop\Protec\Models\IpBlock;

trait CachesIpBlocks
{
    public function warmCache(): int
    {
        if ($this->blockCache() === null) {
            return 0;
        }

        $count = 0;
        $blocks = $this
            ->newBlockModel()
            ->newQuery()
            ->active()
            ->select('ip_address')
            ->distinct()
            ->lazyById(500, column: 'ip_address');

        foreach ($blocks as $block) {
            // Re-read under the mutation lock so an unblock during the refill
            // cannot restore an obsolete block from the enumeration query.
            $this->withIpLock($block->ip_address, fn () => $this->refreshBlockCache($block->ip_address));
            $count++;
        }

        return $count;
    }

    protected function cachedActiveBlock(string $ip): ?IpBlock
    {
        $cache = $this->blockCache();

        if ($cache === null) {
            return $this->findActiveBlock($ip);
        }

        $attributes = $cache->get($this->blockCacheKey($ip));

        if (! is_array($attributes)) {
            return null;
        }

        $model = $this->newBlockModel();
        $block = $model->newFromBuilder($attributes, $model->getConnection()->getName());

        return $block->isActive() ? $block : null;
    }

    protected function blockCache(): ?Repository
    {
        $store = config('protec.cache_store', default: 'default');
        $cache = Cache::store($store === 'default' ? null : $store);

        return $cache->getStore() instanceof DatabaseStore ? null : $cache;
    }

    protected function refreshBlockCache(string $ip): void
    {
        $cache = $this->blockCache();

        if ($cache === null) {
            return;
        }

        $connection = $this->newBlockModel()->getConnection();

        if ($connection->transactionLevel() > 0) {
            // Publish committed state only; an outer transaction can roll back.
            $connection->afterCommit(fn () => $this->withIpLock(
                $ip,
                fn () => $this->refreshBlockCache($ip),
            ));

            return;
        }

        // A shorter overlapping block must not hide a longer or permanent one.
        $block = $this
            ->newBlockModel()
            ->newQuery()
            ->active()
            ->where('ip_address', $ip)
            ->orderByRaw('CASE WHEN expires_at IS NULL THEN 0 ELSE 1 END')
            ->orderByDesc('expires_at')
            ->latest('id')
            ->first();

        if ($block === null) {
            $cache->forget($this->blockCacheKey($ip));

            return;
        }

        // A null expiry stores the entry forever. Only plain attributes are cached.
        $cache->put($this->blockCacheKey($ip), $block->getAttributes(), $block->expires_at);
    }

    protected function blockCacheKey(string $ip): string
    {
        return 'protec:blocked:'.hash('sha256', $ip);
    }
}
