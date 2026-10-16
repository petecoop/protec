<?php

declare(strict_types=1);

use Illuminate\Http\Middleware\TrustProxies;
use Illuminate\Http\Request;
use Petecoop\Protec\Detectors\ScannerProbe;
use Petecoop\Protec\Models\IpBlock;

beforeEach(function () {
    TrustProxies::flushState();
    TrustProxies::withHeaders(Request::HEADER_X_FORWARDED_FOR);
    config()->set('protec.detectors.'.ScannerProbe::class.'.policy.attempts', 1);
});

afterEach(function () {
    TrustProxies::flushState();
    Request::setTrustedProxies([], 0);
});

it('uses the direct client IP when no proxies are trusted and ignores spoofed forwarded headers', function () {
    $this
        ->withServerVariables(['REMOTE_ADDR' => '203.0.113.10'])
        ->withHeader('X-Forwarded-For', '198.51.100.50')
        ->get('/.env')
        ->assertTooManyRequests();

    expect(IpBlock::query()->sole()->ip_address)->toBe('203.0.113.10');
});

it('blocks the client behind a trusted proxy without blocking other clients behind that proxy', function () {
    TrustProxies::at(['10.0.0.10']);
    $this
        ->withServerVariables(['REMOTE_ADDR' => '10.0.0.10'])
        ->withHeader('X-Forwarded-For', '203.0.113.10')
        ->get('/.env')
        ->assertTooManyRequests();

    expect(IpBlock::query()->sole()->ip_address)->toBe('203.0.113.10');
    $this->get('/ok')->assertTooManyRequests();
    $this->withHeader('X-Forwarded-For', '203.0.113.11')->get('/ok')->assertOk();
});

it('ignores forwarded headers from a peer outside the trusted proxy range', function () {
    TrustProxies::at(['10.0.0.0/24']);
    $this
        ->withServerVariables(['REMOTE_ADDR' => '198.51.100.10'])
        ->withHeader('X-Forwarded-For', '203.0.113.10')
        ->get('/.env')
        ->assertTooManyRequests();

    expect(IpBlock::query()->sole()->ip_address)->toBe('198.51.100.10');
});

it('uses the nearest untrusted client in a proxy chain instead of a spoofed leftmost address', function () {
    TrustProxies::at(['10.0.0.0/24']);
    $this
        ->withServerVariables(['REMOTE_ADDR' => '10.0.0.10'])
        ->withHeader('X-Forwarded-For', '198.51.100.99, 203.0.113.10, 10.0.0.11')
        ->get('/.env')
        ->assertTooManyRequests();

    expect(IpBlock::query()->sole()->ip_address)->toBe('203.0.113.10');
});
