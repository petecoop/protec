<?php

declare(strict_types=1);

namespace Petecoop\Protec\Tests\Fixtures;

use Petecoop\Protec\Models\IpBlock;

class CustomBlock extends IpBlock
{
    protected $table = 'custom_ip_blocks';
}
