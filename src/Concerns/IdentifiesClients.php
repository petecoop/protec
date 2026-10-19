<?php

declare(strict_types=1);

namespace Petecoop\Protec\Concerns;

use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\IpUtils;

trait IdentifiesClients
{
    protected function isAllowedIp(Request $request): bool
    {
        $allowed = config('protec.allowed_ips', []);

        if ($allowed === []) {
            return false;
        }

        $ip = $this->resolveIp($request);

        return $ip !== null && IpUtils::checkIp($ip, $allowed);
    }

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
