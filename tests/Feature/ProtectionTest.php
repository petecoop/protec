<?php

declare(strict_types=1);

use Illuminate\Auth\GenericUser;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Event;
use Petecoop\Protec\Data\Detection;
use Petecoop\Protec\Data\Limit;
use Petecoop\Protec\Detectors\ScannerProbe;
use Petecoop\Protec\Events\IpBlocked;
use Petecoop\Protec\Events\IpUnblocked;
use Petecoop\Protec\Facades\Protec;
use Petecoop\Protec\Models\IpBlock;

it('blocks the tenth scanner probe and records a readable IP and expiry', function () {
    Event::fake([IpBlocked::class]);
    $this->freezeSecond();

    for ($attempt = 1; $attempt < 10; $attempt++) {
        $this->get('/wp-admin/setup-config.php')->assertNotFound();
    }

    $this->assertDatabaseCount('protec_ip_blocks', 0);
    $this->get('/wp-admin/setup-config.php')->assertTooManyRequests()->assertHeaderMissing('Retry-After');

    $block = IpBlock::query()->sole();
    expect($block->ip_address)
        ->toBe('127.0.0.1')
        ->and($block->detector)
        ->toBe('scanner-probe')
        ->and($block->reason)
        ->toBeNull()
        ->and($block->expires_at->equalTo(now()->addHour()))
        ->toBeTrue();
    Event::assertDispatchedTimes(IpBlocked::class, 1);
});

it('blocks subsequent application requests before the route runs without extending the block', function () {
    Event::fake([IpBlocked::class]);
    $this->freezeSecond();
    Protec::record(request(), new Detection('test'), new Limit(attempts: 1));
    $expiresAt = IpBlock::query()->sole()->expires_at->toDateTimeString();
    $this->travel(30)->seconds();

    $this->get('/ok')->assertTooManyRequests()->assertDontSee('ok');
    $this->get('/ok')->assertTooManyRequests();

    expect(IpBlock::query()->sole()->expires_at->toDateTimeString())->toBe($expiresAt);
    Event::assertDispatchedTimes(IpBlocked::class, 1);
});

it('keeps a database block effective after the cache is flushed', function () {
    Protec::record(request(), new Detection('test'), new Limit(attempts: 1));
    Cache::flush();

    $this->get('/ok')->assertTooManyRequests();
});

it('allows requests again at the exact block expiration', function () {
    $this->freezeSecond();
    Protec::record(request(), new Detection('test'), new Limit(attempts: 1, blockFor: 60));
    $this->travel(60)->seconds();

    $this->get('/ok')->assertOk();
});

it('resets counting after the observation window expires', function () {
    for ($attempt = 1; $attempt < 10; $attempt++) {
        $this->get('/.env')->assertNotFound();
    }

    $this->travel(61)->seconds();
    $this->get('/.env')->assertNotFound();
    $this->assertDatabaseCount('protec_ip_blocks', 0);
});

it('exempts authenticated requests even when their IP is blocked', function () {
    Protec::record(request(), new Detection('test'), new Limit(attempts: 1));
    $this->actingAs(new GenericUser(['id' => 1]));

    $this->get('/ok')->assertOk();
    $this->get('/.env')->assertNotFound();
    $this->assertDatabaseCount('protec_ip_blocks', 1);
});

it('can include authenticated requests by disabling the exemption', function () {
    config()->set('protec.exemptions', []);
    $this->actingAs(new GenericUser(['id' => 1]));
    Protec::record(request(), new Detection('test'), new Limit(attempts: 1));

    $this->get('/ok')->assertTooManyRequests();
});

it('does not count successful scanner-looking routes or words in query strings', function () {
    for ($attempt = 1; $attempt <= 12; $attempt++) {
        $this->get('/wp-admin/healthy')->assertOk();
        $this->get('/missing?provider=sendgrid&redirect=/wp-admin')->assertNotFound();
    }

    $this->assertDatabaseCount('protec_ip_blocks', 0);
});

it('matches sensitive path probes including encoded paths', function (string $path) {
    $this->get($path)->assertNotFound();
    config()->set('protec.detectors.'.ScannerProbe::class.'.policy.attempts', 2);
    $this->get($path)->assertTooManyRequests();
})->with(['/.env', '/.git/config', '/%2eenv', '/backup.sql', '/wp-login.php']);

it('can disable a detector or the whole package', function () {
    config()->set('protec.detectors.'.ScannerProbe::class, false);
    for ($attempt = 1; $attempt <= 12; $attempt++) {
        $this->get('/.env')->assertNotFound();
    }

    Protec::record(request(), new Detection('test'), new Limit(attempts: 1));
    config()->set('protec.enabled', false);
    $this->get('/ok')->assertOk();
});

it('keeps different clients and reasons independent', function () {
    $request = Illuminate\Http\Request::create('/', server: ['REMOTE_ADDR' => '203.0.113.10']);
    $other = Illuminate\Http\Request::create('/', server: ['REMOTE_ADDR' => '203.0.113.11']);
    $limit = new Limit(attempts: 2);

    expect(Protec::record($request, new Detection('one'), $limit))
        ->toBeNull()
        ->and(Protec::record($other, new Detection('one'), $limit))
        ->toBeNull()
        ->and(Protec::record($request, new Detection('two'), $limit))
        ->toBeNull()
        ->and(Protec::record($request, new Detection('one'), $limit))
        ->toBeInstanceOf(IpBlock::class);
});

it('normalizes IPv6 addresses for blocking and unblocking', function () {
    Event::fake([IpUnblocked::class]);
    $request = Illuminate\Http\Request::create('/', server: [
        'REMOTE_ADDR' => '2001:0db8:0000:0000:0000:0000:0000:0001',
    ]);
    Protec::record($request, new Detection('test'), new Limit(attempts: 1));

    expect(IpBlock::query()->sole()->ip_address)->toBe('2001:db8::1');
    $this->artisan('protec:unblock', ['ip' => '2001:db8::1'])->assertSuccessful();
    expect(IpBlock::query()->sole()->isActive())->toBeFalse();
    Event::assertDispatchedTimes(IpUnblocked::class, 1);
});

it('creates another row after expiration and preserves the original block', function () {
    Event::fake([IpBlocked::class]);
    $this->freezeSecond();
    $limit = new Limit(attempts: 1, blockFor: 60);
    $original = Protec::record(request(), new Detection('one'), $limit);
    $this->travel(60)->seconds();
    Protec::record(request(), new Detection('two'), $limit);

    $this->assertDatabaseCount('protec_ip_blocks', 2);
    expect(IpBlock::query()->latest('id')->first()->reason)
        ->toBe('two')
        ->and($original->fresh()->reason)
        ->toBe('one')
        ->and($original->fresh()->expires_at->equalTo($original->expires_at))
        ->toBeTrue();
    Event::assertDispatchedTimes(IpBlocked::class, 2);
});

it('prunes expired records after retention but retains active and recently expired blocks', function () {
    $this->freezeSecond();
    $attributes = ['detector' => 'application', 'reason' => 'test'];
    IpBlock::create(['ip_address' => '203.0.113.1', 'expires_at' => now()->subDays(31), ...$attributes]);
    IpBlock::create(['ip_address' => '203.0.113.2', 'expires_at' => now()->subDay(), ...$attributes]);
    IpBlock::create(['ip_address' => '203.0.113.3', 'expires_at' => now()->addHour(), ...$attributes]);

    $this->artisan('model:prune', ['--model' => [IpBlock::class]])->assertSuccessful();

    $this->assertDatabaseMissing('protec_ip_blocks', ['ip_address' => '203.0.113.1']);
    $this->assertDatabaseCount('protec_ip_blocks', 2);
});
