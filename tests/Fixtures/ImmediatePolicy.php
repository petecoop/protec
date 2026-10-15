<?php

declare(strict_types=1);

namespace Petecoop\Protec\Tests\Fixtures;

use Illuminate\Http\Request;
use Petecoop\Protec\Contracts\Policy;
use Petecoop\Protec\Data\Detection;
use Petecoop\Protec\Data\Limit;

class ImmediatePolicy implements Policy
{
    public function evaluate(Detection $detection, Request $request): Limit
    {
        return new Limit(attempts: 1, blockFor: 120);
    }
}
