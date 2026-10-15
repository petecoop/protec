# Protec

![Protec artwork](artwork/he-protec-but-he-also-attac-400.png)

`petecoop/protec` detects suspicious requests to your Laravel application and implements permanent / temporary client IP blocks.

## Installation

```sh
composer require petecoop/protec
php artisan vendor:publish --tag=protec-config
php artisan vendor:publish --tag=protec-migrations
php artisan migrate
```

Configure middleware in `bootstrap/app.php`:

```php
use Illuminate\Foundation\Configuration\Middleware;
use Petecoop\Protec\Middleware\InspectRequests;
use Petecoop\Protec\Middleware\ProtectRequests;

->withMiddleware(function (Middleware $middleware): void {
    $middleware->append(InspectRequests::class);
    $middleware->web(append: [ProtectRequests::class]);
    $middleware->api(append: [ProtectRequests::class]); // If the app has API routes.
})
```

`InspectRequests` inspects responses globally, including unrouted 404s. `ProtectRequests` checks existing blocks and request detectors before route actions execute. Its middleware priority follows session and authentication middleware. The `protec` route middleware alias is also available for individual route groups.

Authenticated requests are exempt by default, using the request's current authenticated user. For API routes, run the appropriate authentication middleware before Protec. Change `exemptions` to use another guard or include authenticated users.

## Livewire exceptions

To count corrupt snapshots and attempts to change locked properties, add these hooks to the application's existing `withExceptions` callback:

```php
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Http\Request;
use Petecoop\Protec\Protec;
use Symfony\Component\HttpFoundation\Response;

->withExceptions(function (Exceptions $exceptions): void {
    $exceptions->respond(
        fn (Response $response, Throwable $exception, Request $request): Response =>
            app(Protec::class)->handleException($response, $exception, $request),
    );

    $exceptions->dontReportWhen(
        fn (Throwable $exception): bool =>
            app(Protec::class)->shouldIgnoreException($exception, request()),
    );
})
```

Merge the response logic if the app already has a `respond` callback: Laravel keeps one final response callback. Protec preserves the original exception response below the block threshold. It identifies Livewire exception types on the update route; an ordinary 419 response does not count. Set `report_livewire_tampering` to `true` to keep reporting those exceptions.

The final response hook matters because Livewire's corrupt-payload exception can render its own response before Laravel's exception rendering callbacks run. Protec does not replace Livewire's update route or checksum verification.

## Default detectors and policies

| Detector                      | Trigger                                                                                     | Threshold                                    | Block duration |
| ----------------------------- | ------------------------------------------------------------------------------------------- | -------------------------------------------- | -------------- |
| `ScannerProbe`                | A 404 for a known probe path, including `.env`, `.git`, WordPress, PHPUnit, and SQL backups | 10 within 60 seconds                         | 1 hour         |
| `CorruptLivewirePayload`      | Livewire corrupt-snapshot or locked-property exception                                      | 5 within 10 minutes                          | 10 minutes     |
| `DisallowedLivewireComponent` | Guest requests a component outside the configured list                                      | Disabled; when enabled, 20 within 10 minutes | 10 minutes     |

The threshold request creates the block and returns an empty 429. Later requests from that IP also return 429. Requests do not extend an active block. Counters are separate for each IP, detector class, and reason, using Laravel's `RateLimiter`. Configure Laravel's cache limiter store for shared counters across application servers. Persisted blocks survive cache flushes.

Scanner patterns match decoded paths case-insensitively, using Laravel wildcard matching. Query strings and successful routes are ignored. Paths are application-relative, without a leading slash.

Published config lists detector classes with their policy and options:

```php
'detectors' => [
    \Petecoop\Protec\Detectors\ScannerProbe::class => [
        'policy' => \Petecoop\Protec\Policies\RateLimitPolicy::class,
        'options' => ['attempts' => 10, 'within' => 60, 'block_for' => 3600],
    ],
],
```

Set a detector entry to `false`, or its `enabled` option to `false`, to disable it. Set the package's `enabled` to `false` to skip detection and enforcement. Policy options are seconds, except `attempts`. A policy can also set `reject_with` to reject each matching request before the block threshold; `GuestComponentPolicy` defaults to 401.

### Restrict guest Livewire components

Enable `DisallowedLivewireComponent` and configure every component that guests should be able to update:

```php
'livewire' => [
    'guest_components' => [
        \App\Livewire\Login::class,
        \App\Livewire\ResetPassword::class,
        'public-counter',
    ],
    'read_only_components' => ['notifications'],
],
```

Names and class names are normalized using Livewire's component finder. An enabled detector with an empty guest list rejects all guest component updates. Every component in a batched request must be allowed. A read-only component must also be in the guest list; it rejects property updates but **still permits action calls**. This supports components such as notification handlers, and is not an authorization boundary for their actions.

Component names in incoming snapshots are untrusted until Livewire verifies the checksum. A rejected name records an attempted request, not evidence that a component was successfully accessed. Continue authorizing sensitive component actions, queries, and uploads inside your application.

## Trusted proxies and IP addresses

Protec uses `$request->ip()` exclusively to identify a client and normalizes IPv4/IPv6 addresses before lookup and persistence. It does not read forwarded headers itself or maintain a second proxy trust list. Configure Laravel's trusted proxies for your deployment in `bootstrap/app.php`, for example:

```php
use Illuminate\Http\Request;

$middleware->trustProxies(
    at: ['10.0.0.0/24'], // Replace with the actual ingress proxy addresses.
    headers: Request::HEADER_X_FORWARDED_FOR,
);
```

Trust the proxy addresses and header format used by your ingress. An untrusted peer's forwarded headers are ignored. A trusted proxy must overwrite or correctly append client headers. Trusting every peer while allowing direct origin access lets clients influence their apparent IP. Without the correct proxy trust, the proxy's address can be blocked instead of the client.

IP addresses are stored in readable form. Only the internal rate-limit cache key is hashed. Shared IP addresses share a block; the default authenticated-user exemption still applies.

## Customizing behaviour

### Extend Protec through the container

Bind a subclass in an application service provider's `register` method:

```php
$this->app->bind(
    \Petecoop\Protec\Protec::class,
    \App\Support\Protec::class,
);
```

Middleware, the facade, exception hooks, and the unblock command all resolve that binding. There is no actions configuration or separate action-class extension mechanism.

```php
namespace App\Support;

use Illuminate\Http\Request;
use Petecoop\Protec\Models\IpBlock;
use Petecoop\Protec\Protec as BaseProtec;
use Symfony\Component\HttpFoundation\Response;

class Protec extends BaseProtec
{
    public function respond(Request $request, ?IpBlock $block = null, int $status = 429): Response
    {
        return response()->json(['message' => 'Request blocked.'], $status);
    }
}
```

Public methods include `shouldInspect`, `blocked`, `inspect`, `record`, `respond`, `unblock`, and the exception hooks. Protected extension points include:

- `resolveIp` and `normalizeIp` for client identification. Preserve Laravel's trusted-proxy boundary when overriding.
- `newBlockModel`, `findActiveBlock`, `blockIp`, and `blockAttributes` for block storage and attributes.
- `recordActivity` and `rateLimitKey` for activity counting.
- `enforce` for applying a policy's decision, and `detectors` for resolving the registry.

Internal calls use `$this`, so overriding one method affects the normal flow without replacing the rest of the implementation.

### Extend a detector's patterns

```php
namespace App\Protec;

use Petecoop\Protec\Detectors\ScannerProbe;

class ApplicationScanner extends ScannerProbe
{
    public function patterns(): array
    {
        return [...parent::patterns(), 'private-admin/*', 'debug.php'];
    }
}
```

Bind the existing detector to the subclass to retain its config and counter identity:

```php
$this->app->bind(
    \Petecoop\Protec\Detectors\ScannerProbe::class,
    \App\Protec\ApplicationScanner::class,
);
```

Alternatively, disable the original detector and add the subclass as another config entry. Avoid enabling both unless you intend overlapping detections to count separately.

### Add detectors, policies, and exemptions

A detector implements `Contracts\Detector` and returns a `Data\Detection` or `null` from `detect(Data\Inspection $inspection)`. `Inspection` contains the request, an optional response, and an optional exception. Select the appropriate phase in your detector so a request is counted once.

A policy implements `Contracts\Policy::evaluate(Detection $detection, Request $request): Limit`. `Limit` contains `attempts`, `within`, `blockFor`, and optional `rejectWith`. Policies are resolved through the container with the detector's `options` constructor parameter. Add the detector and policy classes to config; the container can inject their dependencies. For behaviour beyond numeric thresholds, subclass a policy or implement the contract.

An exemption implements `Contracts\Exemption::applies(Request $request): bool`. Add its class to `exemptions`. A matching exemption skips both detection and existing blocks. Remove `AuthenticatedRequests` to apply protection to authenticated users too.

### Replace the block model

Extend `Models\IpBlock` and set the `model` config entry to that subclass. It is used for lookup, creation, reactivation, and unblocking. If you change its table or connection, provide the corresponding migration. The model supports Laravel's `Prunable` trait.

## Operations and events

```sh
php artisan protec:unblock 203.0.113.10
php artisan model:prune --model='Petecoop\Protec\Models\IpBlock'
```

Unblocking expires the record and clears its associated detector/reason counter. Other detector counters keep their own observation windows. `retention_days` defaults to 30 days after expiration. Schedule Laravel's `model:prune` command if desired, using your configured model class.

There is one database row per canonical IP. A later block reactivates the expired row with the new reason and expiry. Listen to events if you need an append-only history or application notifications:

- `ActivityDetected`: IP address, detector class, detection, and current attempt count.
- `IpBlocked`: the block model, emitted once per new or reactivated block.
- `IpUnblocked`: the manually expired block model.

Built-in detections store a matched pattern, component name, or exception class. They do not persist raw Livewire snapshots, request bodies, or credentials.

To record an application-specific signal directly:

```php
use Petecoop\Protec\Data\Detection;
use Petecoop\Protec\Data\Limit;
use Petecoop\Protec\Facades\Protec;

$block = Protec::record(
    request(),
    new Detection('application-signal', ['rule' => 'example']),
    new Limit(attempts: 3, within: 60, blockFor: 600),
);
```

`record` returns the active block or `null`; the caller decides whether to return `Protec::respond(request(), $block)` immediately.
