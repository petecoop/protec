<?php

declare(strict_types=1);

namespace Petecoop\Protec\Data;

use InvalidArgumentException;
use Petecoop\Protec\Duration;

class Limit
{
    public readonly int $within;

    public readonly ?int $blockFor;

    public function __construct(
        public readonly int $attempts = 5,
        int|string $within = 600,
        int|string|null $blockFor = 600,
        public readonly ?int $rejectWith = null,
    ) {
        $this->within = Duration::seconds($within);
        $this->blockFor = $blockFor === null ? null : Duration::seconds($blockFor);

        if ($attempts < 1 || $this->within < 1 || $this->blockFor !== null && $this->blockFor < 1) {
            throw new InvalidArgumentException(
                'Protec attempts, within, and blockFor must be positive integers; blockFor may be null for a permanent ban.',
            );
        }

        if ($rejectWith !== null && ($rejectWith < 400 || $rejectWith > 599)) {
            throw new InvalidArgumentException('Protec rejectWith must be an HTTP error status.');
        }
    }

    /** @param array{attempts?: int, within?: int|string, block_for?: int|string|null, reject_with?: int|null} $policy */
    public static function fromConfig(array $policy): self
    {
        return new self(
            attempts: $policy['attempts'] ?? 5,
            within: $policy['within'] ?? 600,
            blockFor: array_key_exists('block_for', $policy) ? $policy['block_for'] : 600,
            rejectWith: $policy['reject_with'] ?? null,
        );
    }
}
