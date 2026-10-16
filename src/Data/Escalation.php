<?php

declare(strict_types=1);

namespace Petecoop\Protec\Data;

use InvalidArgumentException;
use Petecoop\Protec\Duration;
use Petecoop\Protec\Models\IpBlock;

class Escalation
{
    public readonly int $within;

    public readonly ?int $blockFor;

    public function __construct(
        public readonly int $after = 5,
        int|string $within = '8h',
        int|string|null $blockFor = '7d',
    ) {
        $this->within = Duration::seconds($within);
        $this->blockFor = $blockFor === null ? null : Duration::seconds($blockFor);

        if ($after < 2 || $this->within < 1 || $this->blockFor !== null && $this->blockFor < 1) {
            throw new InvalidArgumentException(
                'Escalation requires after >= 2 and positive durations or a null blockFor.',
            );
        }
    }

    /** @param array<string, mixed> $attributes
     * @return array<string, mixed>
     */
    public function apply(IpBlock $block, array $attributes): array
    {
        $previousBlocks = $block
            ->newQuery()
            ->where('ip_address', $block->ip_address)
            ->where('detector', $attributes['detector'])
            ->where('created_at', '>', now()->subSeconds($this->within))
            ->count();

        if (($previousBlocks + 1) >= $this->after && $attributes['expires_at'] !== null) {
            $attributes['expires_at'] = $this->blockFor === null
                ? null
                : max($attributes['expires_at'], now()->addSeconds($this->blockFor));
        }

        return $attributes;
    }
}
