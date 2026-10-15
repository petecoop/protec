<?php

declare(strict_types=1);

namespace Petecoop\Protec\Events;

use Petecoop\Protec\Models\IpBlock;

class IpBlocked
{
    public function __construct(
        public readonly IpBlock $block,
    ) {}
}
