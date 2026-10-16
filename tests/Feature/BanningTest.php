<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Event;
use Petecoop\Protec\Data\Detection;
use Petecoop\Protec\Data\Limit;
use Petecoop\Protec\Detectors\ScannerProbe;
use Petecoop\Protec\Events\IpBlocked;
use Petecoop\Protec\Facades\Protec;
use Petecoop\Protec\Models\IpBlock;

it('can permanently ban on the first matching request through detector options', function () {
    config()->set('protec.detectors.'.ScannerProbe::class.'.policy', ['attempts' => 1, 'block_for' => null]);

    $this->get('/.env')->assertTooManyRequests();
    expect(IpBlock::query()->sole()->expires_at)->toBeNull();
    $this->travel(365)->days();
    Cache::flush();
    $this->get('/ok')->assertTooManyRequests();
    $this->artisan('model:prune', ['--model' => [IpBlock::class]])->assertSuccessful();
    $this->assertDatabaseCount('protec_ip_blocks', 1);
    $this->artisan('protec:unblock', ['ip' => '127.0.0.1'])->assertSuccessful();
    $this->get('/ok')->assertOk();
});

it('can ban immediately for a configured duration', function () {
    $this->freezeSecond();
    config()->set('protec.detectors.'.ScannerProbe::class.'.policy', ['attempts' => 1, 'block_for' => '2d']);

    $this->get('/.env')->assertTooManyRequests();
    expect(IpBlock::query()->sole()->expires_at->equalTo(now()->addDays(2)))->toBeTrue();
    $this->travel(2)->days();
    $this->get('/ok')->assertOk();
});

it('allows permanent blocks after a rate-limit threshold as well', function () {
    config()->set('protec.detectors.'.ScannerProbe::class.'.policy', [
        'attempts' => 2,
        'within' => 60,
        'block_for' => null,
    ]);

    $this->get('/.env')->assertNotFound();
    $this->get('/.env')->assertTooManyRequests();
    expect(IpBlock::query()->sole()->expires_at)->toBeNull();
});

it('supports explicit bans and can upgrade an active temporary block to permanent', function () {
    $this->freezeSecond();
    Protec::record(request(), new Detection('test'), new Limit(attempts: 1));
    $block = Protec::ban('127.0.0.1', reason: 'manual-review', context: ['reference' => 'case-1']);

    expect($block->expires_at)
        ->toBeNull()
        ->and($block->reason)
        ->toBe('manual-review')
        ->and($block->context)
        ->toBe(['reference' => 'case-1']);
    $this->assertDatabaseCount('protec_ip_blocks', 1);
    $this->get('/ok')->assertTooManyRequests();
    expect(Protec::unblock('127.0.0.1'))->toBeTrue();
    $this->get('/ok')->assertOk();
});

it('canonicalizes IPv6 for explicit bans and rejects invalid arguments', function () {
    $block = Protec::ban('2001:0db8:0000:0000:0000:0000:0000:0001', for: 60);
    expect($block->ip_address)->toBe('2001:db8::1');
    expect(fn () => Protec::ban('invalid'))->toThrow(InvalidArgumentException::class);
    expect(fn () => Protec::ban('203.0.113.1', for: 0))->toThrow(InvalidArgumentException::class);
});

it('escalates the fifth new block within eight hours to seven days for one detector', function () {
    Event::fake([IpBlocked::class]);
    $this->freezeSecond();
    config()->set('protec.detectors.'.ScannerProbe::class.'.escalation', [
        'after' => 5,
        'within' => '8h',
        'block_for' => '7d',
    ]);

    for ($offence = 1; $offence <= 5; $offence++) {
        $block = Protec::record(
            request(),
            new Detection('test'),
            new Limit(attempts: 1, blockFor: 60),
            ScannerProbe::class,
        );
        $expected = $offence === 5 ? now()->addDays(7) : now()->addMinute();
        expect($block->expires_at->equalTo($expected))->toBeTrue();

        // Hits during a block must neither create a new offence nor extend it.
        for ($attempt = 1; $attempt <= 3; $attempt++) {
            $this->get('/ok')->assertTooManyRequests();
        }
        expect(IpBlock::query()->sole()->block_history['scanner-probe'])->toHaveCount($offence);
        Cache::flush();
        $this->travel(60)->seconds();
    }

    $this->assertDatabaseCount('protec_ip_blocks', 1);
    Event::assertDispatchedTimes(IpBlocked::class, 5);
});

it('uses a rolling escalation window rather than a fixed window', function () {
    $this->freezeSecond();
    config()->set('protec.detectors.'.ScannerProbe::class.'.escalation', [
        'after' => 3,
        'within' => 100,
        'block_for' => null,
    ]);
    $limit = new Limit(attempts: 1, blockFor: 1);
    Protec::record(request(), new Detection('test'), $limit, ScannerProbe::class);
    $this->travel(90)->seconds();
    Protec::record(request(), new Detection('test'), $limit, ScannerProbe::class);
    $this->travel(20)->seconds();
    $block = Protec::record(request(), new Detection('test'), $limit, ScannerProbe::class);
    expect($block->expires_at)
        ->not
        ->toBeNull()
        ->and($block->block_history['scanner-probe'])
        ->toHaveCount(2);
    $this->travel(1)->seconds();
    $block = Protec::record(request(), new Detection('test'), $limit, ScannerProbe::class);
    expect($block->expires_at)->toBeNull()->and($block->block_history['scanner-probe'])->toHaveCount(3);
});

it('excludes offences at the exact escalation window boundary', function () {
    $this->freezeSecond();
    config()->set('protec.detectors.'.ScannerProbe::class.'.escalation', [
        'after' => 2,
        'within' => 60,
        'block_for' => null,
    ]);
    $limit = new Limit(attempts: 1, blockFor: 1);
    Protec::record(request(), new Detection('test'), $limit, ScannerProbe::class);
    $this->travel(60)->seconds();
    $block = Protec::record(request(), new Detection('test'), $limit, ScannerProbe::class);

    expect($block->expires_at)
        ->not
        ->toBeNull()
        ->and($block->block_history['scanner-probe'])
        ->toHaveCount(1);
});

it('keeps offence histories independent for each IP', function () {
    config()->set('protec.detectors.'.ScannerProbe::class.'.escalation', [
        'after' => 2,
        'within' => 60,
        'block_for' => null,
    ]);
    $first = Illuminate\Http\Request::create('/', server: ['REMOTE_ADDR' => '203.0.113.1']);
    $second = Illuminate\Http\Request::create('/', server: ['REMOTE_ADDR' => '203.0.113.2']);
    $limit = new Limit(attempts: 1, blockFor: 1);
    Protec::record($first, new Detection('test'), $limit, ScannerProbe::class);
    $this->travel(1)->seconds();
    expect(Protec::record($second, new Detection('test'), $limit, ScannerProbe::class)->expires_at)->not->toBeNull();
    expect(Protec::record($first, new Detection('test'), $limit, ScannerProbe::class)->expires_at)->toBeNull();
});

it('never shortens a block when the escalation duration is smaller', function () {
    $this->freezeSecond();
    config()->set('protec.detectors.'.ScannerProbe::class.'.escalation', [
        'after' => 2,
        'within' => 600,
        'block_for' => 1,
    ]);
    $limit = new Limit(attempts: 1, blockFor: 60);
    Protec::record(request(), new Detection('test'), $limit, ScannerProbe::class);
    $this->travel(60)->seconds();
    $block = Protec::record(request(), new Detection('test'), $limit, ScannerProbe::class);

    expect($block->expires_at->equalTo(now()->addMinute()))->toBeTrue();
});

it('retains recent escalation history even when pruning retention is zero', function () {
    config()->set('protec.detectors.'.ScannerProbe::class.'.escalation', [
        'after' => 5,
        'within' => '8h',
        'block_for' => '7d',
    ]);
    config()->set('protec.retention', 0);
    Protec::record(request(), new Detection('test'), new Limit(attempts: 1, blockFor: 1), ScannerProbe::class);
    $this->travel(2)->seconds();
    $this->artisan('model:prune', ['--model' => [IpBlock::class]])->assertSuccessful();
    $this->assertDatabaseCount('protec_ip_blocks', 1);
    $this->travel(8)->hours();
    $this->artisan('model:prune', ['--model' => [IpBlock::class]])->assertSuccessful();
    $this->assertDatabaseCount('protec_ip_blocks', 0);
});

it('does not count manual bans as automatic offences', function () {
    config()->set('protec.detectors.'.ScannerProbe::class.'.escalation', [
        'after' => 5,
        'within' => '8h',
        'block_for' => '7d',
    ]);
    Protec::ban('127.0.0.1', for: 1);
    expect(IpBlock::query()->sole()->block_history)->toBeNull();
});

it('keeps escalation histories separate for different detectors at the same IP', function () {
    $this->freezeSecond();
    $scanner = ScannerProbe::class;
    $livewire = Petecoop\Protec\Detectors\CorruptLivewirePayload::class;
    foreach ([$scanner, $livewire] as $detector) {
        config()->set('protec.detectors.'.$detector.'.escalation', [
            'after' => 2,
            'within' => '8h',
            'block_for' => null,
        ]);
    }
    $limit = new Limit(attempts: 1, blockFor: 1);
    Protec::record(request(), new Detection('test'), $limit, $scanner);
    $this->travel(1)->seconds();
    $block = Protec::record(request(), new Detection('test'), $limit, $livewire);
    expect($block->expires_at)->not->toBeNull();
    $this->travel(1)->seconds();
    $block = Protec::record(request(), new Detection('test'), $limit, $scanner);
    expect($block->expires_at)
        ->toBeNull()
        ->and($block->block_history['scanner-probe'])
        ->toHaveCount(2)
        ->and($block->block_history['corrupt-livewire-payload'])
        ->toHaveCount(1);
});

it('can disable escalation for one detector while enabling it for another', function () {
    $this->freezeSecond();
    config()->set('protec.detectors.'.ScannerProbe::class.'.escalation', false);
    config()->set('protec.detectors.'.Petecoop\Protec\Detectors\CorruptLivewirePayload::class.'.escalation', [
        'after' => 2,
        'within' => '8h',
        'block_for' => null,
    ]);
    $limit = new Limit(attempts: 1, blockFor: 1);
    for ($attempt = 1; $attempt <= 3; $attempt++) {
        $block = Protec::record(request(), new Detection('test'), $limit, ScannerProbe::class);
        expect($block->expires_at)->not->toBeNull()->and($block->block_history)->toBeNull();
        $this->travel(1)->seconds();
    }
});

it('accepts shorthand durations for explicit bans', function () {
    $this->freezeSecond();
    expect(Protec::ban('203.0.113.1', for: '1h 30m')->expires_at->equalTo(now()->addMinutes(90)))->toBeTrue();
});

it('preserves the longest detector escalation window during pruning', function () {
    $this->freezeSecond();
    config()->set('protec.retention', 0);
    config()->set('protec.detectors.'.ScannerProbe::class.'.escalation', [
        'after' => 2,
        'within' => '1h',
        'block_for' => '1d',
    ]);
    config()->set('protec.detectors.'.Petecoop\Protec\Detectors\CorruptLivewirePayload::class.'.escalation', [
        'after' => 2,
        'within' => '8h',
        'block_for' => '7d',
    ]);
    Protec::record(request(), new Detection('test'), new Limit(attempts: 1, blockFor: 1), ScannerProbe::class);
    $this->travel(2)->hours();
    $this->artisan('model:prune', ['--model' => [IpBlock::class]])->assertSuccessful();
    $this->assertDatabaseCount('protec_ip_blocks', 1);
    $this->travel(7)->hours();
    $this->artisan('model:prune', ['--model' => [IpBlock::class]])->assertSuccessful();
    $this->assertDatabaseCount('protec_ip_blocks', 0);
});
