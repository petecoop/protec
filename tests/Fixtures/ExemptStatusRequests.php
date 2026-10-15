<?php

declare(strict_types=1);

namespace Petecoop\Protec\Tests\Fixtures;

use Illuminate\Http\Request;
use Petecoop\Protec\Contracts\Exemption;

class ExemptStatusRequests implements Exemption
{
    public function applies(Request $request): bool
    {
        return $request->is('ok');
    }
}
