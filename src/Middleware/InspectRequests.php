<?php

declare(strict_types=1);

namespace Petecoop\Protec\Middleware;

use Closure;
use Illuminate\Http\Request;
use Petecoop\Protec\Data\Inspection;
use Petecoop\Protec\Protec;
use Symfony\Component\HttpFoundation\Response;

/**
 * Global response inspection includes unrouted 404s. Authentication is resolved
 * after the inner Laravel middleware has loaded the session or API guard.
 */
class InspectRequests
{
    public function __construct(
        protected Protec $protec,
    ) {}

    /** @param Closure(Request): Response $next */
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);

        return $this->protec->inspect(new Inspection($request, $response)) ?? $response;
    }
}
