<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use Petecoop\Protec\Data\Detection;
use Petecoop\Protec\Data\Limit;
use Petecoop\Protec\Detectors\ScannerProbe;
use Petecoop\Protec\Events\IpUnblocked;
use Petecoop\Protec\Facades\Protec;
use Petecoop\Protec\Models\IpBlock;

it('counts blocks created before escalation was enabled', function () {
    $this->freezeSecond();
    $limit = new Limit(attempts: 1, blockFor: 1);

    for ($offence = 1; $offence <= 3; $offence++) {
        Protec::record(request(), new Detection, $limit, ScannerProbe::class);
        $this->travel(1)->seconds();
    }

    config()->set('protec.detectors.'.ScannerProbe::class.'.escalation', [
        'after' => 4,
        'within' => '8h',
        'block_for' => '7d',
    ]);
    $block = Protec::record(request(), new Detection, $limit, ScannerProbe::class);

    expect($block->expires_at->equalTo(now()->addDays(7)))->toBeTrue();
    $this->assertDatabaseCount('protec_ip_blocks', 4);
});

it('can increase the escalation threshold without losing earlier blocks', function () {
    $this->freezeSecond();
    config()->set('protec.detectors.'.ScannerProbe::class.'.escalation', [
        'after' => 2,
        'within' => '8h',
        'block_for' => 1,
    ]);
    $limit = new Limit(attempts: 1, blockFor: 1);
    for ($offence = 1; $offence <= 3; $offence++) {
        Protec::record(request(), new Detection, $limit, ScannerProbe::class);
        $this->travel(1)->seconds();
    }

    config()->set('protec.detectors.'.ScannerProbe::class.'.escalation', [
        'after' => 4,
        'within' => '8h',
        'block_for' => null,
    ]);
    expect(Protec::record(request(), new Detection, $limit, ScannerProbe::class)->expires_at)->toBeNull();
});

it('counts manually lifted automatic blocks by creation time and across reasons', function () {
    $this->freezeSecond();
    $limit = new Limit(attempts: 1);
    Protec::record(request(), new Detection('one'), $limit, ScannerProbe::class);
    Protec::unblock('127.0.0.1');

    config()->set('protec.detectors.'.ScannerProbe::class.'.escalation', [
        'after' => 2,
        'within' => '1m',
        'block_for' => null,
    ]);
    expect(Protec::record(request(), new Detection('two'), $limit, ScannerProbe::class)->expires_at)->toBeNull();
});

it('does not treat a recent unblock as a new offence', function () {
    $this->freezeSecond();
    $limit = new Limit(attempts: 1);
    Protec::record(request(), new Detection, $limit, ScannerProbe::class);
    $this->travel(61)->seconds();
    Protec::unblock('127.0.0.1');

    config()->set('protec.detectors.'.ScannerProbe::class.'.escalation', [
        'after' => 2,
        'within' => '1m',
        'block_for' => null,
    ]);
    expect(Protec::record(request(), new Detection, $limit, ScannerProbe::class)->expires_at)->not->toBeNull();
});

it('allows manual blocks without either a detector or a reason', function () {
    $block = Protec::block('203.0.113.1');

    expect($block->fresh()->detector)->toBeNull()->and($block->reason)->toBeNull();
});

it('lifts every active block for an IP while preserving the original records', function () {
    Event::fake([IpUnblocked::class]);
    $this->freezeSecond();
    $expired = Protec::block('203.0.113.1', for: 1);
    $this->travel(1)->seconds();
    $temporary = Protec::block('203.0.113.1', for: '1d');
    $permanent = Protec::block('203.0.113.1', reason: 'reviewed');
    $other = Protec::block('203.0.113.2');

    expect(Protec::unblock('203.0.113.1'))->toBeTrue();
    expect($temporary->fresh()->expires_at->equalTo($temporary->expires_at))
        ->toBeTrue()
        ->and($temporary->fresh()->unblocked_at->equalTo(now()))
        ->toBeTrue()
        ->and($permanent->fresh()->expires_at)
        ->toBeNull()
        ->and($permanent->fresh()->isActive())
        ->toBeFalse()
        ->and($expired->fresh()->unblocked_at)
        ->toBeNull()
        ->and($other->fresh()->isActive())
        ->toBeTrue()
        ->and(IpBlock::query()->active()->where('ip_address', '203.0.113.1')->exists())
        ->toBeFalse()
        ->and(Protec::unblock('203.0.113.1'))
        ->toBeFalse();
    Event::assertDispatchedTimes(IpUnblocked::class, 2);
    $this->assertDatabaseCount('protec_ip_blocks', 4);
});

it('prunes lifted permanent and temporary blocks after retention from unblocking', function () {
    $this->freezeSecond();
    config()->set('protec.retention', '1d');
    $permanent = Protec::block('203.0.113.1');
    $temporary = Protec::block('203.0.113.2', for: '1y');
    Protec::unblock('203.0.113.1');
    Protec::unblock('203.0.113.2');
    $this->travel(1)->days();
    $active = Protec::block('203.0.113.3');

    $this->artisan('model:prune', ['--model' => [IpBlock::class]])->assertSuccessful();
    expect($permanent->fresh())
        ->toBeNull()
        ->and($temporary->fresh())
        ->toBeNull()
        ->and($active->fresh()->isActive())
        ->toBeTrue();
});

it('retains lifted automatic blocks for the configured escalation window', function () {
    $this->freezeSecond();
    config()->set('protec.retention', 0);
    config()->set('protec.detectors.'.ScannerProbe::class.'.escalation', [
        'after' => 2,
        'within' => '8h',
        'block_for' => null,
    ]);
    $block = Protec::record(request(), new Detection, new Limit(attempts: 1), ScannerProbe::class);
    Protec::unblock('127.0.0.1');

    $this->artisan('model:prune', ['--model' => [IpBlock::class]])->assertSuccessful();
    expect($block->fresh())->not->toBeNull();
    $this->travel(8)->hours();
    $this->artisan('model:prune', ['--model' => [IpBlock::class]])->assertSuccessful();
    expect($block->fresh())->toBeNull();
});

it('indexes active lookups, escalation counts, and pruning without making IPs unique', function () {
    $indexes = collect(Schema::getIndexes('protec_ip_blocks'));

    foreach ([
        ['ip_address', 'unblocked_at', 'expires_at'],
        ['ip_address', 'detector', 'created_at'],
        ['expires_at'],
        ['unblocked_at'],
    ] as $columns) {
        expect($indexes->contains(
            fn (array $index): bool => $index['columns'] === $columns && ! $index['unique'],
        ))->toBeTrue();
    }
    expect(Schema::hasColumn('protec_ip_blocks', 'block_history'))->toBeFalse();
});
