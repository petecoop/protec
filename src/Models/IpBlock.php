<?php

declare(strict_types=1);

namespace Petecoop\Protec\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Prunable;
use Illuminate\Support\Carbon;

/**
 * @property string $ip_address
 * @property string $detector
 * @property string $reason
 * @property array<string, mixed>|null $context
 * @property Carbon $expires_at
 */
class IpBlock extends Model
{
    use Prunable;

    protected $table = 'protec_ip_blocks';

    protected $fillable = ['ip_address', 'detector', 'reason', 'context', 'expires_at'];

    protected function casts(): array
    {
        return ['context' => 'array', 'expires_at' => 'datetime'];
    }

    /** @param Builder<static> $query */
    public function scopeActive(Builder $query): void
    {
        $query->where('expires_at', '>', now());
    }

    public function isActive(): bool
    {
        return $this->expires_at->isFuture();
    }

    /** @return Builder<static> */
    public function prunable(): Builder
    {
        return static::query()
            ->where('expires_at', '<=', now()->subDays(max(0, (int) config('protec.retention_days', default: 30))));
    }
}
