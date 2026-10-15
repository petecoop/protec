<?php

declare(strict_types=1);

namespace Petecoop\Protec\Middleware;

use Closure;
use Illuminate\Http\Request;
use Petecoop\Protec\Data\Inspection;
use Petecoop\Protec\Protec;
use Symfony\Component\HttpFoundation\Response;

/**
 * Route middleware rejects blocked clients and disallowed component requests
 * before application code runs, after session/authentication middleware.
 */
class ProtectRequests
{
    public function __construct(
        protected Protec $protec,
    ) {}

    /** @param Closure(Request): Response $next */
    public function handle(Request $request, Closure $next): Response
    {
        return $this->protec->inspect(new Inspection($request)) ?? $next($request);
    }
}
