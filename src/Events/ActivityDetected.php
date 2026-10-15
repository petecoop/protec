<?php

declare(strict_types=1);

namespace Petecoop\Protec\Events;

use Petecoop\Protec\Data\Detection;

class ActivityDetected
{
    public function __construct(
        public readonly string $ipAddress,
        public readonly string $detector,
        public readonly Detection $detection,
        public readonly int $attempts,
    ) {}
}
