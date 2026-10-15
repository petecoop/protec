<?php

declare(strict_types=1);

namespace Petecoop\Protec\Contracts;

use Illuminate\Http\Request;
use Petecoop\Protec\Data\Detection;
use Petecoop\Protec\Data\Limit;

interface Policy
{
    public function evaluate(Detection $detection, Request $request): Limit;
}
