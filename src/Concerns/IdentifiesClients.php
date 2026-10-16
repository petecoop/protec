<?php

declare(strict_types=1);

namespace Petecoop\Protec\Concerns;

use Illuminate\Http\Request;

trait IdentifiesClients
{
    protected function resolveIp(Request $request): ?string
    {
        // Laravel determines the client using its configured trusted proxies.
        // Never read forwarded headers independently of that trust boundary.
        return $this->normalizeIp($request->ip());
    }

    protected function normalizeIp(?string $ip): ?string
    {
        if ($ip === null || filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return null;
        }

        return inet_ntop(inet_pton($ip));
    }
}
