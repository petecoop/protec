<?php

declare(strict_types=1);

namespace Petecoop\Protec\Exemptions;

use Illuminate\Http\Request;
use Petecoop\Protec\Contracts\Exemption;

class AuthenticatedRequests implements Exemption
{
    public function applies(Request $request): bool
    {
        return $request->user() !== null;
    }
}
