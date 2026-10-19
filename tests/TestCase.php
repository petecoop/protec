<?php

declare(strict_types=1);

namespace Petecoop\Protec\Tests;

use Illuminate\Support\Facades\Route;
use Livewire\Livewire;
use Livewire\LivewireServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;
use Petecoop\Protec\ProtecServiceProvider;
use Petecoop\Protec\Tests\Fixtures\Counter;
use Symfony\Component\HttpFoundation\Response;

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

        (require __DIR__.'/../database/migrations/create_ip_blocks_table.php')->up();

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
