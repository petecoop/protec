<?php

declare(strict_types=1);

namespace Petecoop\Protec\Facades;

use Illuminate\Support\Facades\Facade;

/** @mixin \Petecoop\Protec\Protec */
class Protec extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return \Petecoop\Protec\Protec::class;
    }
}
