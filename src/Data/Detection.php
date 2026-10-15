<?php

declare(strict_types=1);

namespace Petecoop\Protec\Data;

class Detection
{
    /** @param array<string, mixed> $context */
    public function __construct(
        public readonly string $reason,
        public readonly array $context = [],
    ) {}
}
