<?php

declare(strict_types=1);

namespace Petecoop\Protec\Data;

use InvalidArgumentException;

class Limit
{
    public function __construct(
        public readonly int $attempts = 5,
        public readonly int $within = 600,
        public readonly int $blockFor = 600,
        public readonly ?int $rejectWith = null,
    ) {
        if ($attempts < 1 || $within < 1 || $blockFor < 1) {
            throw new InvalidArgumentException('Protec attempts, within, and blockFor must be positive integers.');
        }

        if ($rejectWith !== null && ($rejectWith < 400 || $rejectWith > 599)) {
            throw new InvalidArgumentException('Protec rejectWith must be an HTTP error status.');
        }
    }
}
