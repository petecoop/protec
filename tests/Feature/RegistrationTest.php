<?php

declare(strict_types=1);

use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Support\Facades\Route;
use Livewire\Livewire;
use Petecoop\Protec\Detectors\CorruptLivewirePayload;
use Petecoop\Protec\Middleware\ProtectRequests;
use Petecoop\Protec\ProtecServiceProvider;
use Symfony\Component\HttpFoundation\Response;

it('automatically protects web and api middleware groups', function () {
    $kernel = $this->app->make(Kernel::class);
    expect($kernel->getMiddlewareGroups()['web'])
        ->toContain(ProtectRequests::class)
        ->and($kernel->getMiddlewareGroups()['api'])
        ->toContain(ProtectRequests::class);

    Route::middleware('api')->get('/api/example', fn () => response('example'));
    Petecoop\Protec\Facades\Protec::ban('127.0.0.1');
    $this->get('/api/example')->assertTooManyRequests()->assertDontSee('example');
});

it('preserves application error response callbacks when inspecting Livewire failures', function () {
    $handler = $this->app->make(ExceptionHandler::class);
    $handler->respondUsing(function (Response $response): Response {
        $response->headers->set('X-App-Error', 'handled');

        return $response;
    });
    $snapshot = $this->counterSnapshot();
    $snapshot['data']['count'] = 99;
    config()->set('protec.detectors.'.CorruptLivewirePayload::class.'.policy.attempts', 2);

    $this->postJson(Livewire::getUpdateUri(), $this->payload($snapshot), [
        'X-Livewire' => 'true',
    ])->assertStatus(419)->assertHeader('X-App-Error', 'handled');
    $this->postJson(Livewire::getUpdateUri(), $this->payload($snapshot), ['X-Livewire' => 'true'])
        ->assertTooManyRequests();
    $this->assertDatabaseCount('protec_ip_blocks', 1);
});

it('also detects Livewire exceptions when the app renders a plain Symfony response', function () {
    $handler = $this->app->make(ExceptionHandler::class);
    $handler->respondUsing(
        fn (Response $response): Response => new Response('application error', $response->getStatusCode()),
    );
    $snapshot = $this->counterSnapshot();
    $snapshot['data']['count'] = 99;
    config()->set('protec.detectors.'.CorruptLivewirePayload::class.'.policy.attempts', 1);

    $this->postJson(Livewire::getUpdateUri(), $this->payload($snapshot), ['X-Livewire' => 'true'])
        ->assertTooManyRequests();
});

it('suppresses known tampering before app reporting callbacks and honours the reporting option', function () {
    $reported = false;
    $this->app
        ->make(ExceptionHandler::class)
        ->reportable(function (Throwable $exception) use (&$reported): bool {
            $reported = true;

            return false;
        });
    $snapshot = $this->counterSnapshot();
    $snapshot['data']['count'] = 99;

    $this->postJson(Livewire::getUpdateUri(), $this->payload($snapshot), ['X-Livewire' => 'true'])->assertStatus(419);
    expect($reported)->toBeFalse();

    config()->set('protec.detectors.'.CorruptLivewirePayload::class.'.report', true);
    // Livewire's exception has its own report() in production. Debug allows
    // Laravel's regular reporting callbacks to run for this assertion.
    config()->set('app.debug', true);
    $this->postJson(Livewire::getUpdateUri(), $this->payload($snapshot), [
        'X-Livewire' => 'true',
    ])->assertInternalServerError();
    expect($reported)->toBeTrue();
});

it('leaves unrelated errors and their reporting alone', function () {
    $reported = false;
    $handler = $this->app->make(ExceptionHandler::class);
    $handler->reportable(function (RuntimeException $exception) use (&$reported): bool {
        $reported = true;

        return false;
    });
    $handler->respondUsing(fn (Response $response): Response => response('application error', status: 503));
    Route::middleware('web')->get('/error', fn () => throw new RuntimeException('Application failure'));

    $this->get('/error')->assertServiceUnavailable()->assertSee('application error');
    expect($reported)->toBeTrue();
    $this->assertDatabaseCount('protec_ip_blocks', 0);
});

it('does not leak captured exceptions into later requests', function () {
    $snapshot = $this->counterSnapshot();
    $snapshot['data']['count'] = 99;
    $this->postJson(Livewire::getUpdateUri(), $this->payload($snapshot), ['X-Livewire' => 'true'])->assertStatus(419);

    for ($attempt = 1; $attempt <= 6; $attempt++) {
        $this->get('/ok')->assertOk();
    }
    $this->assertDatabaseCount('protec_ip_blocks', 0);
});

it('keeps registration idempotent when booted again after the kernel and handler are resolved', function () {
    $this->app->make(ExceptionHandler::class);
    $kernel = $this->app->make(Kernel::class);
    (new ProtecServiceProvider($this->app))->boot($this->app['router']);
    expect(array_keys($kernel->getMiddlewareGroups()['web'], ProtectRequests::class, strict: true))->toHaveCount(1);
    $snapshot = $this->counterSnapshot();
    $snapshot['data']['count'] = 99;
    config()->set('protec.detectors.'.CorruptLivewirePayload::class.'.policy.attempts', 2);

    $this->postJson(Livewire::getUpdateUri(), $this->payload($snapshot), ['X-Livewire' => 'true'])->assertStatus(419);
    $this->assertDatabaseCount('protec_ip_blocks', 0);
    $this->postJson(Livewire::getUpdateUri(), $this->payload($snapshot), [
        'X-Livewire' => 'true',
    ])->assertTooManyRequests();
});
