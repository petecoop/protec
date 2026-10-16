<p align="center"><img width="400" src="artwork/he-protec-but-he-also-attac-400.png" alt="Protec"></p>

## Introduction

`petecoop/protec` detects suspicious requests to your Laravel application and applies temporary or permanent IP blocks. It uses Laravel's rate limiter, stores blocks in an Eloquent model, and includes protection for Livewire update requests.

Supports Laravel 12/13 and PHP 8.3+. Livewire 4 is optional. Authenticated users are exempt by default.

## Installation

```sh
composer require petecoop/protec
php artisan vendor:publish --tag=protec-migrations
php artisan migrate
```

To customize the defaults:

```sh
php artisan vendor:publish --tag=protec-config
```

## Usage

Detectors identify suspicious activity, such as scanner probes or invalid Livewire payloads. Each detector has a `policy` array that sets how many matches to allow and how long to block the client's IP. Configure them under `detectors` in `config/protec.php`.

Protec counts matches for each IP, detector, and reason. The shared options are:

- `attempts`: the number of matches that triggers a block.
- `within`: the counting window.
- `block_for`: the block duration; use `null` for a permanent ban.
- `reject_with`: an optional HTTP error status to return for each match before the block threshold.

Durations accept integer seconds or strings, such as `30s`, `10m`, `8h`, `7d`, `2w`, or `1h 30m`. This applies to policy durations, escalation, and retention. Values must resolve to whole seconds.

For example, these settings block after 10 matches within 60 seconds, for one hour:

```php
'policy' => ['attempts' => 10, 'within' => 60, 'block_for' => '1h'],
```

The threshold request and subsequent blocked requests receive an empty 429. `reject_with` controls the response before the block threshold. Further requests do not extend an active block. Set a detector entry to `false` to disable it.

### Bans

Set `block_for` to `null` to permanently ban the IP address given the matching rule. To immediately ban on the first request set the `attempts` to 1.

```php
'policy' => ['attempts' => 1, 'block_for' => null],
```

You can also ban an IP directly:

```php
use Petecoop\Protec\Facades\Protec;

Protec::ban('203.0.113.10'); // Permanent until manually unblocked.
Protec::ban('203.0.113.11', for: '2d', reason: 'manual-review');
```

An explicit ban replaces the IP's current block. Exemptions still apply when enforcing bans; remove `AuthenticatedRequests` from `exemptions` to include signed-in users.

### Repeat offenders

Add an `escalation` array inside a detector's config entry to escalate a repeating offender:

```php
'escalation' => [
    'after' => 3, // number of times the offending detector can trigger
    'within' => '8h', // within this time period
    'block_for' => '7d', // null makes the escalated ban permanent.
],
```

Counts are separate for each detector and IP, using a rolling window. Set that detector's `escalation` to `false` to disable it. Requests during an active block and manual bans do not add offences. Escalation never shortens the original block duration.

## Blocking Scanners

`ScannerProbe` detects requests for common scanner targets, including WordPress paths, exposed configuration files, database tools, and framework debugging endpoints. It only counts matching 404 responses; successful routes and query strings do not count.

It is enabled by default and blocks for one hour after 10 matches within 60 seconds. Its `patterns` list accepts built-in sets and custom strings, with exclusions under `except`:

```php
use Petecoop\Protec\Patterns;

// Inside 'detectors' in config/protec.php:
\Petecoop\Protec\Detectors\ScannerProbe::class => [
    'policy' => ['attempts' => 10, 'within' => '1m', 'block_for' => '1h'],
    'escalation' => ['after' => 5, 'within' => '8h', 'block_for' => '7d'],
    'patterns' => [
        'my-custom-pattern/*',
        Patterns::WORDPRESS,
        Patterns::CONFIGURATION,
        Patterns::VERSION_CONTROL,
    ],
    'except' => ['ignore-this-route'],
],
```

Add or remove entries in `patterns` to select the sets you need.

Patterns match decoded paths without a leading slash, case-insensitively, with `*` wildcards..

## Livewire

Livewire protection works automatically on its update route.

### Corrupt payloads

`CorruptLivewirePayload` detects invalid snapshot checksums and attempts to change locked properties. Configure its entry under `detectors` using the shared policy settings:

```php
\Petecoop\Protec\Detectors\CorruptLivewirePayload::class => [
    'policy' => ['attempts' => 5, 'within' => '10m', 'block_for' => '10m'],
],
```

Below the threshold, the original error response is preserved. Ordinary 419 responses do not count. Known tampering is suppressed from application error reporting by default; set the top-level `report_livewire_tampering` option to `true` to keep it in the application's normal reporting flow.

### Guest component restrictions

`DisallowedLivewireComponent` restricts which components guests may update. Livewire has strong protections but this is intended to add a layer of protection from accidentally exposing sensitive data, and to catch and block scanners trying to exploit. It is disabled by default. Enable its entry under `detectors` after listing the components guests need:

```php
\Petecoop\Protec\Detectors\DisallowedLivewireComponent::class => [
    'enabled' => true,
    'policy' => ['attempts' => 20, 'within' => '10m', 'block_for' => '10m', 'reject_with' => 401],
],
```

These options reject each disallowed request with 401, then block for 10 minutes after 20 matches within 10 minutes. Disallowed component requests are always rejected; omitting `reject_with` keeps the default 401. Set it to another HTTP error status to change the initial rejection.

Set the allowed component names or classes in the top-level `livewire` section:

```php
'livewire' => [
    'guest_components' => [\App\Livewire\Login::class, 'public-counter'],
    'read_only_components' => [],
],
```

An empty guest list rejects all guest component updates when the detector is enabled. Every component in a batch must be allowed. Add allowed guest components to `read_only_components` to reject property updates; their action calls are still permitted.

Incoming component names are untrusted: a rejected request does not prove successful access. Continue authorizing sensitive actions, queries, and uploads inside components.

## Additional information

### Unblocking and pruning

Unblock an IP through the facade or Artisan:

```php
\Petecoop\Protec\Facades\Protec::unblock('203.0.113.10');
```

```sh
php artisan protec:unblock 203.0.113.10
php artisan model:prune --model='Petecoop\Protec\Models\IpBlock'
```

Expired records are retained for `retention` (`'30d'` by default), and at least the longest enabled detector escalation window. Integer retention values are seconds; use `0` to prune immediately once escalation history is no longer needed. Permanent bans are never pruned. Schedule `model:prune` as needed. One row is maintained per IP; events `ActivityDetected`, `IpBlocked`, and `IpUnblocked` are available for logging or an audit history.

### Customisation

This package is designed to be easy to customise. Implement the interfaces in `Petecoop\Protec\Contracts` to create your own detectors and exemptions and add them to the config. Extend the `Petecoop\Models\IpBlock` model and set the `model` option in the config to override it. `Protec` can be overriden / extended in Laravel's container.

### Proxies

Client IPs come from Laravel's `$request->ip()` and are normalized for IPv4/IPv6. Configure Laravel's trusted proxies for your ingress so the client is identified correctly. Untrusted forwarded headers are ignored. IP blocks affect clients sharing an IP; multi-server apps should use a shared Laravel rate-limiter cache store and database.
