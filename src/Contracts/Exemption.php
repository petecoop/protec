<?php

declare(strict_types=1);

namespace Petecoop\Protec\Contracts;

use Illuminate\Http\Request;

interface Exemption
{
    public function applies(Request $request): bool;
}
