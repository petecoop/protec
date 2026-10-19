<?php

declare(strict_types=1);

use Illuminate\Http\Middleware\TrustProxies;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Livewire\Livewire;
use Petecoop\Protec\Detectors\CorruptLivewirePayload;
use Petecoop\Protec\Detectors\GuestLivewireComponents;
use Petecoop\Protec\Detectors\ScannerProbe;
use Petecoop\Protec\Events\ActivityDetected;
use Petecoop\Protec\Facades\Protec;
use Petecoop\Protec\Models\IpBlock;
use Petecoop\Protec\Tests\Fixtures\CustomProtec;

beforeEach(function () {
    TrustProxies::flushState();
    TrustProxies::withHeaders(Request::HEADER_X_FORWARDED_FOR);
    config()->set('protec.detectors.'.ScannerProbe::class.'.policy.attempts', 1);
});

afterEach(function () {
    TrustProxies::flushState();
    Request::setTrustedProxies([], 0);
});

it('allows configured IPs and ranges while protecting other clients', function (
    string $allowed,
    string $client,
    string $other,
) {
    config()->set('protec.allowed_ips', [$allowed]);

    $this->withServerVariables(['REMOTE_ADDR' => $client])->get('/.env')->assertNotFound();
    $this->assertDatabaseCount('ip_blocks', 0);
    $this->withServerVariables(['REMOTE_ADDR' => $other])->get('/.env')->assertTooManyRequests();

    expect(IpBlock::query()->sole()->ip_address)->toBe($other);
})->with([
    'IPv4 address' => ['203.0.113.10', '203.0.113.10', '203.0.113.11'],
    'IPv4 range' => ['198.51.100.0/24', '198.51.100.99', '198.51.101.99'],
    'equivalent IPv6 address' => ['2001:db8::10', '2001:0db8:0000:0000:0000:0000:0000:0010', '2001:db8::11'],
    'IPv6 range' => ['2001:db8:1234::/48', '2001:db8:1234::1', '2001:db8:1235::1'],
]);

it('bypasses existing manual blocks independently of other exemptions', function (string $store) {
    config()->set([
        'protec.allowed_ips' => ['127.0.0.1'],
        'protec.exemptions' => [],
        'cache.default' => $store,
        'cache.limiter' => 'array',
        'cache.stores.sql-cache' => ['driver' => 'database', 'connection' => 'testing', 'table' => 'unused_cache'],
    ]);
    $block = Protec::block('127.0.0.1');
    DB::enableQueryLog();

    $this->get('/ok')->assertOk();
    expect(DB::getQueryLog())->toBeEmpty();
    expect($block->fresh()->isActive())->toBeTrue();

    config()->set('protec.allowed_ips', []);
    $this->get('/ok')->assertTooManyRequests();
})->with(['cached block' => 'array', 'database block' => 'sql-cache']);

it('does not record attempts from an allowed scanner', function () {
    Event::fake([ActivityDetected::class]);
    config()->set('protec.allowed_ips', ['127.0.0.1']);
    config()->set('protec.detectors.'.ScannerProbe::class.'.policy.attempts', 2);

    for ($attempt = 1; $attempt <= 6; $attempt++) {
        $this->get('/.env')->assertNotFound();
    }
    Event::assertNotDispatched(ActivityDetected::class);
    $this->assertDatabaseCount('ip_blocks', 0);

    config()->set('protec.allowed_ips', []);
    $this->get('/.env')->assertNotFound();
    $this->get('/.env')->assertTooManyRequests();
});

it('skips Livewire restrictions and detection while leaving Livewire validation intact', function () {
    $payload = $this->payload($this->counterSnapshot());
    $payload['components'][0]['calls'] = [['method' => 'deleteUser', 'params' => []]];
    config()->set('protec.allowed_ips', ['127.0.0.1']);
    config()->set('protec.detectors.'.GuestLivewireComponents::class.'.enabled', true);
    config()->set('protec.detectors.'.CorruptLivewirePayload::class.'.policy.attempts', 1);

    $this->postJson(Livewire::getUpdateUri(), $payload, ['X-Livewire' => 'true'])->assertStatus(419);
    $this->postJson(Livewire::getUpdateUri(), $payload, ['X-Livewire' => 'true'])->assertStatus(419);
    $this->assertDatabaseCount('ip_blocks', 0);
});

it('allows a client behind a trusted proxy without allowing every client behind it', function () {
    config()->set('protec.allowed_ips', ['203.0.113.10']);
    TrustProxies::at(['10.0.0.10']);

    $this
        ->withServerVariables(['REMOTE_ADDR' => '10.0.0.10'])
        ->withHeader('X-Forwarded-For', '203.0.113.10')
        ->get('/.env')
        ->assertNotFound();
    $this->withHeader('X-Forwarded-For', '203.0.113.11')->get('/.env')->assertTooManyRequests();
    expect(IpBlock::query()->sole()->ip_address)->toBe('203.0.113.11');
});

it('does not trust a spoofed allowed IP in forwarded headers from an untrusted client', function () {
    config()->set('protec.allowed_ips', ['203.0.113.10']);

    $this
        ->withServerVariables(['REMOTE_ADDR' => '198.51.100.10'])
        ->withHeader('X-Forwarded-For', '203.0.113.10')
        ->get('/.env')
        ->assertTooManyRequests();
    expect(IpBlock::query()->sole()->ip_address)->toBe('198.51.100.10');
});

it('ignores a spoofed allowlisted address earlier in a trusted proxy chain', function () {
    config()->set('protec.allowed_ips', ['198.51.100.99']);
    TrustProxies::at(['10.0.0.0/24']);

    $this
        ->withServerVariables(['REMOTE_ADDR' => '10.0.0.10'])
        ->withHeader('X-Forwarded-For', '198.51.100.99, 203.0.113.10, 10.0.0.11')
        ->get('/.env')
        ->assertTooManyRequests();
    expect(IpBlock::query()->sole()->ip_address)->toBe('203.0.113.10');
});

it('honours the Protec container binding when resolving allowlisted clients', function () {
    $this->app->bind(Petecoop\Protec\Protec::class, CustomProtec::class);
    config()->set('protec.allowed_ips', ['203.0.113.99']);

    $this->get('/.env')->assertNotFound();
    $this->assertDatabaseCount('ip_blocks', 0);
});
