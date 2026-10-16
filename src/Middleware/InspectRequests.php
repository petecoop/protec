<?php

declare(strict_types=1);

namespace Petecoop\Protec\Middleware;

use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response as LaravelResponse;
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
        $request->attributes->remove('protec.exception');
        $response = $next($request);

        // Laravel attaches the original exception after rendering it, including
        // exceptions that implement their own render() method in Livewire.
        $exception =
            $response instanceof LaravelResponse || $response instanceof JsonResponse
                ? $response->exception ?? $request->attributes->get('protec.exception')
                : $request->attributes->get('protec.exception');

        if ($exception !== null) {
            return $this->protec->handleException($response, $exception, $request);
        }

        return $this->protec->inspect(new Inspection($request, $response)) ?? $response;
    }
}
