<?php

declare(strict_types=1);

namespace Petecoop\Protec\Tests;

use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Foundation\Exceptions\Handler;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Livewire\Livewire;
use Livewire\LivewireServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;
use Petecoop\Protec\Middleware\InspectRequests;
use Petecoop\Protec\Middleware\ProtectRequests;
use Petecoop\Protec\Protec;
use Petecoop\Protec\ProtecServiceProvider;
use Petecoop\Protec\Tests\Fixtures\Counter;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

abstract class TestCase extends Orchestra
{
    protected function getPackageProviders($app): array
    {
        return [LivewireServiceProvider::class, ProtecServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('t', times: 32)));
        $app['config']->set('app.debug', false);
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);
        $app['config']->set('cache.default', 'array');
        $app['config']->set('session.driver', 'array');
    }

    protected function setUp(): void
    {
        parent::setUp();

        (require __DIR__.'/../database/migrations/create_protec_ip_blocks_table.php')->up();

        $this->app->make(Kernel::class)->pushMiddleware(InspectRequests::class);
        $this->app['router']->pushMiddlewareToGroup('web', ProtectRequests::class);

        /** @var Handler $handler */
        $handler = $this->app->make(ExceptionHandler::class);
        $handler->respondUsing(
            static fn (
                Response $response,
                Throwable $exception,
                Request $request,
            ): Response => app(Protec::class)->handleException($response, $exception, $request),
        );
        $handler->dontReportWhen(static fn (Throwable $exception): bool => app(Protec::class)->shouldIgnoreException(
            $exception,
            request(),
        ));

        Livewire::component('counter', Counter::class);
        Route::middleware('web')->get('/counter', static fn (): string => Livewire::mount('counter'));
        Route::middleware('web')->get('/ok', static fn (): Response => response('ok'));
        Route::middleware('web')->get('/wp-admin/healthy', static fn (): Response => response('ok'));
    }

    /** @return array<string, mixed> */
    public function counterSnapshot(): array
    {
        $response = $this->get('/counter')->assertOk();
        preg_match('/wire:snapshot="([^"]+)"/', $response->getContent(), $matches);

        return json_decode(
            html_entity_decode($matches[1], ENT_QUOTES | ENT_HTML5),
            associative: true,
            flags: JSON_THROW_ON_ERROR,
        );
    }

    /** @param array<string, mixed> $snapshot
     * @param array<string, mixed> $updates
     * @return array<string, mixed>
     */
    public function payload(array $snapshot, array $updates = []): array
    {
        return [
            'components' => [[
                'snapshot' => json_encode($snapshot, JSON_THROW_ON_ERROR),
                'updates' => $updates,
                'calls' => [['method' => '$refresh', 'params' => []]],
            ]],
        ];
    }
}
