<?php

declare(strict_types=1);

namespace Petecoop\Protec\Data;

use InvalidArgumentException;

class Detection
{
    /** @param array<string, mixed> $context */
    public function __construct(
        public readonly string $reason,
        public readonly array $context = [],
        public readonly ?int $rejectWith = null,
    ) {
        if ($rejectWith !== null && ($rejectWith < 400 || $rejectWith > 599)) {
            throw new InvalidArgumentException('A detection rejection must be an HTTP error status.');
        }
    }
}
