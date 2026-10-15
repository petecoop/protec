<?php

declare(strict_types=1);

use Illuminate\Auth\GenericUser;
use Illuminate\Support\Facades\Route;
use Livewire\Livewire;
use Petecoop\Protec\Detectors\CorruptLivewirePayload;
use Petecoop\Protec\Detectors\DisallowedLivewireComponent;
use Petecoop\Protec\Models\IpBlock;

it('counts genuine checksum failures and blocks on the fifth without counting twice', function () {
    $snapshot = $this->counterSnapshot();
    $snapshot['data']['count'] = 99;

    for ($attempt = 1; $attempt < 5; $attempt++) {
        $this->postJson(Livewire::getUpdateUri(), $this->payload($snapshot), [
            'X-Livewire' => 'true',
        ])->assertStatus(419);
    }

    $this->assertDatabaseCount('protec_ip_blocks', 0);
    $this->postJson(Livewire::getUpdateUri(), $this->payload($snapshot), [
        'X-Livewire' => 'true',
    ])->assertTooManyRequests();
    expect(IpBlock::query()->sole()->reason)->toBe('corrupt-livewire-payload');
});

it('counts locked property tampering using a valid snapshot', function () {
    $snapshot = $this->counterSnapshot();
    config()->set('protec.detectors.'.CorruptLivewirePayload::class.'.options.attempts', 1);

    $this->postJson(Livewire::getUpdateUri(), $this->payload($snapshot, ['lockedValue' => 'changed']), [
        'X-Livewire' => 'true',
    ])->assertTooManyRequests();
});

it('does not classify ordinary 419 responses as tampering', function () {
    Route::middleware('web')->post('/expired-session', fn () => response('', status: 419));

    for ($attempt = 1; $attempt <= 7; $attempt++) {
        $this->postJson('/expired-session')->assertStatus(419);
    }

    $this->assertDatabaseCount('protec_ip_blocks', 0);
});

it('exempts authenticated users from Livewire tampering detection', function () {
    $snapshot = $this->counterSnapshot();
    $snapshot['data']['count'] = 99;
    $this->actingAs(new GenericUser(['id' => 1]));

    for ($attempt = 1; $attempt <= 6; $attempt++) {
        $this->postJson(Livewire::getUpdateUri(), $this->payload($snapshot), [
            'X-Livewire' => 'true',
        ])->assertStatus(419);
    }

    $this->assertDatabaseCount('protec_ip_blocks', 0);
});

it('denies valid snapshots for disallowed components before executing their actions', function () {
    $snapshot = $this->counterSnapshot();
    config()->set('protec.detectors.'.DisallowedLivewireComponent::class.'.enabled', true);
    config()->set('protec.detectors.'.DisallowedLivewireComponent::class.'.options.attempts', 2);

    $this->postJson(Livewire::getUpdateUri(), $this->payload($snapshot), [
        'X-Livewire' => 'true',
    ])->assertUnauthorized();
    $this->postJson(Livewire::getUpdateUri(), $this->payload($snapshot), [
        'X-Livewire' => 'true',
    ])->assertTooManyRequests();
});

it('allows configured guest components and rejects read-only property updates', function () {
    $snapshot = $this->counterSnapshot();
    config()->set('protec.detectors.'.DisallowedLivewireComponent::class.'.enabled', true);
    config()->set('protec.livewire.guest_components', ['counter']);
    config()->set('protec.livewire.read_only_components', ['counter']);

    $this->postJson(Livewire::getUpdateUri(), $this->payload($snapshot), ['X-Livewire' => 'true'])->assertOk();
    $this->postJson(Livewire::getUpdateUri(), $this->payload($snapshot, ['count' => 10]), [
        'X-Livewire' => 'true',
    ])->assertUnauthorized();
});

it('does not allow a mixed batch containing a disallowed component', function () {
    $snapshot = $this->counterSnapshot();
    config()->set('protec.detectors.'.DisallowedLivewireComponent::class.'.enabled', true);
    config()->set('protec.livewire.guest_components', ['counter']);
    $payload = $this->payload($snapshot);
    $snapshot['memo']['name'] = 'private-component';
    $payload['components'][] = $this->payload($snapshot)['components'][0];

    $this->postJson(Livewire::getUpdateUri(), $payload, ['X-Livewire' => 'true'])->assertUnauthorized();
});

it('leaves checksum verification in place for allowlisted components', function () {
    $snapshot = $this->counterSnapshot();
    $snapshot['checksum'] = str_repeat('0', times: 64);
    config()->set('protec.detectors.'.DisallowedLivewireComponent::class.'.enabled', true);
    config()->set('protec.livewire.guest_components', ['counter']);

    $this->postJson(Livewire::getUpdateUri(), $this->payload($snapshot), ['X-Livewire' => 'true'])->assertStatus(419);
});
