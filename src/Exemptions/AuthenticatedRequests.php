<?php

declare(strict_types=1);

namespace Petecoop\Protec\Exemptions;

use Illuminate\Http\Request;
use Petecoop\Protec\Contracts\Exemption;

class AuthenticatedRequests implements Exemption
{
    public function applies(Request $request): bool
    {
        if ($request->user() !== null) {
            return true;
        }

        // Livewire restores persistent route middleware after snapshot verification.
        // Check server-configured session guards before that point without changing
        // the default guard or trusting authentication hints in the payload.
        foreach (config('auth.guards', []) as $guard => $configuration) {
            if (($configuration['driver'] ?? null) === 'session' && $request->user($guard) !== null) {
                return true;
            }
        }

        return false;
    }
}
