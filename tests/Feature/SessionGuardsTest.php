<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Livewire\Livewire;
use Petecoop\Protec\Detectors\CorruptLivewirePayload;
use Petecoop\Protec\Detectors\GuestLivewireComponents;
use Petecoop\Protec\Exemptions\AuthenticatedRequests;
use Petecoop\Protec\Facades\Protec;
use Petecoop\Protec\Models\IpBlock;

beforeEach(function () {
    config()->set('auth.guards.admin', ['driver' => 'session', 'provider' => 'admins']);
    config()->set('auth.providers.admins', ['driver' => 'database', 'table' => 'admins']);
    Schema::create('admins', function (Blueprint $table): void {
        $table->id();
        $table->string('remember_token')->nullable();
    });
    DB::table('admins')->insert(['id' => 1]);
    config()->set('protec.detectors.'.GuestLivewireComponents::class.'.enabled', true);
});

it('recognizes a session guard before Livewire restores persistent authentication', function (
    array $exemptions,
    int $blockedStatus,
) {
    config()->set('protec.exemptions', $exemptions);
    Route::middleware(['web', 'auth:admin'])->get('/admin-counter', fn () => Livewire::mount('counter'));
    $this->withSession([Auth::guard('admin')->getName() => 1]);
    $response = $this->get('/admin-counter')->assertOk();
    preg_match('/wire:snapshot="([^"]+)"/', $response->getContent(), $matches);
    $snapshot = json_decode(html_entity_decode($matches[1], ENT_QUOTES | ENT_HTML5), associative: true);

    // A fresh update request starts with the default guard and no cached users.
    Auth::shouldUse('web');
    Auth::forgetGuards();
    $response = $this->postJson(Livewire::getUpdateUri(), $this->payload($snapshot, ['count' => 10]), [
        'X-Livewire' => 'true',
    ])->assertOk();
    $updated = json_decode($response->json('components.0.snapshot'), associative: true);
    expect($updated['data']['count'])->toBe(10);
    $this->assertDatabaseCount('ip_blocks', 0);

    Protec::block('127.0.0.1');
    Auth::shouldUse('web');
    Auth::forgetGuards();
    $this->postJson(Livewire::getUpdateUri(), $this->payload($snapshot), ['X-Livewire' => 'true'])
        ->assertStatus($blockedStatus);
})->with([
    'authenticated users exempt' => [[AuthenticatedRequests::class], 200],
    'authenticated users protected' => [[], 429],
]);

it('keeps guest restrictions guest-only when the default guard is authenticated', function () {
    $snapshot = $this->counterSnapshot();
    config()->set('protec.exemptions', []);
    $this->actingAs(new Illuminate\Auth\GenericUser(['id' => 1]));

    $this->postJson(Livewire::getUpdateUri(), $this->payload($snapshot, ['count' => 10]), [
        'X-Livewire' => 'true',
    ])->assertOk();
    $this->assertDatabaseCount('ip_blocks', 0);
});

it('still detects tampering by session-authenticated users when exemptions are removed', function () {
    $snapshot = $this->counterSnapshot();
    $snapshot['data']['count'] = 99;
    config()->set('protec.exemptions', []);
    config()->set('protec.detectors.'.CorruptLivewirePayload::class.'.policy.attempts', 1);
    $this->withSession([Auth::guard('admin')->getName() => 1]);
    Auth::forgetGuards();

    $this->postJson(Livewire::getUpdateUri(), $this->payload($snapshot), ['X-Livewire' => 'true'])
        ->assertTooManyRequests();
    expect(IpBlock::query()->sole()->detector)->toBe('corrupt-livewire-payload');
});

it('does not treat a guest as authenticated based on snapshot route metadata', function () {
    $snapshot = $this->counterSnapshot();
    $snapshot['memo']['path'] = 'admin-counter';
    Route::middleware(['web', 'auth:admin'])->get('/admin-counter', fn () => Livewire::mount('counter'));

    $this->postJson(Livewire::getUpdateUri(), $this->payload($snapshot), ['X-Livewire' => 'true'])
        ->assertUnauthorized();
});

it('checks session guards without switching guards or resolving unrelated authentication drivers', function () {
    config()->set('auth.guards.external', ['driver' => 'unregistered-driver']);
    $this->withSession([Auth::guard('admin')->getName() => 1]);
    Auth::forgetGuards();
    Route::middleware('web')->get('/guard-check', function () {
        expect(app(AuthenticatedRequests::class)->applies(request()))->toBeTrue();
        expect(Auth::getDefaultDriver())->toBe('web');
        expect(request()->user())->toBeNull();

        return response('ok');
    });

    $this->get('/guard-check')->assertOk();
});
