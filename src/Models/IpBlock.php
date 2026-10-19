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
 * @property string|null $detector
 * @property string|null $reason
 * @property array<string, mixed>|null $context
 * @property Carbon|null $expires_at
 * @property Carbon|null $unblocked_at
 */
class IpBlock extends Model
{
    use Prunable;

    protected $fillable = ['ip_address', 'detector', 'reason', 'context', 'expires_at', 'unblocked_at'];

    protected function casts(): array
    {
        return ['context' => 'array', 'expires_at' => 'datetime', 'unblocked_at' => 'datetime'];
    }

    /** @param Builder<static> $query */
    public function scopeActive(Builder $query): void
    {
        $query
            ->whereNull('unblocked_at')
            ->where(static fn (Builder $query): Builder => $query->whereNull('expires_at')->orWhere(
                'expires_at',
                '>',
                now(),
            ));
    }

    public function isActive(): bool
    {
        return $this->unblocked_at === null && ($this->expires_at === null || $this->expires_at->isFuture());
    }

    /** @return Builder<static> */
    public function prunable(): Builder
    {
        $cutoff = now()->subSeconds(Duration::seconds(config('protec.retention', default: '30d')));
        $query = static::query()
            ->where(static function (Builder $query) use ($cutoff): void {
                $query
                    ->where('unblocked_at', '<=', $cutoff)
                    ->orWhere(static fn (Builder $query): Builder => $query->whereNull('unblocked_at')
                        ->where('expires_at', '<=', $cutoff));
            });

        $historyWindow = app(DetectorRegistry::class)->historyWindow();

        if ($historyWindow > 0) {
            $query->where('created_at', '<=', now()->subSeconds($historyWindow));
        }

        return $query;
    }
}
