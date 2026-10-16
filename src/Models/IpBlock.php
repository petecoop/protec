<?php

declare(strict_types=1);

namespace Petecoop\Protec\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Prunable;
use Illuminate\Support\Carbon;
use Petecoop\Protec\DetectorRegistry;
use Petecoop\Protec\Duration;

/**
 * @property string $ip_address
 * @property string $detector
 * @property string $reason
 * @property array<string, mixed>|null $context
 * @property Carbon|null $expires_at
 * @property array<string, list<int>>|null $block_history
 */
class IpBlock extends Model
{
    use Prunable;

    protected $table = 'protec_ip_blocks';

    protected $fillable = ['ip_address', 'detector', 'reason', 'context', 'expires_at', 'block_history'];

    protected function casts(): array
    {
        return ['context' => 'array', 'block_history' => 'array', 'expires_at' => 'datetime'];
    }

    /** @param Builder<static> $query */
    public function scopeActive(Builder $query): void
    {
        $query->where(static fn (Builder $query): Builder => $query->whereNull('expires_at')->orWhere(
            'expires_at',
            '>',
            now(),
        ));
    }

    public function isActive(): bool
    {
        return $this->expires_at === null || $this->expires_at->isFuture();
    }

    /** @return Builder<static> */
    public function prunable(): Builder
    {
        $query = static::query()
            ->where(
                'expires_at',
                '<=',
                now()->subSeconds(Duration::seconds(config('protec.retention', default: '30d'))),
            );

        $historyWindow = app(DetectorRegistry::class)->historyWindow();

        if ($historyWindow > 0) {
            $query->where('updated_at', '<=', now()->subSeconds($historyWindow));
        }

        return $query;
    }
}
