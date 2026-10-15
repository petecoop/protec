<?php

declare(strict_types=1);

namespace Petecoop\Protec;

use Illuminate\Contracts\Auth\Middleware\AuthenticatesRequests;
use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Foundation\Http\Kernel;
use Illuminate\Routing\Router;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\ServiceProvider;
use Petecoop\Protec\Commands\UnblockIpCommand;
use Petecoop\Protec\Middleware\ProtectRequests;

class ProtecServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/protec.php', 'protec');
    }

    public function boot(Router $router): void
    {
        $router->aliasMiddleware('protec', ProtectRequests::class);

        $this->publishes([__DIR__.'/../config/protec.php' => config_path('protec.php')], 'protec-config');
        $this->publishesMigrations([
            __DIR__.'/../database/migrations/create_protec_ip_blocks_table.php' => database_path(
                'migrations/create_protec_ip_blocks_table.php',
            ),
        ], 'protec-migrations');

        if ($this->app->runningInConsole()) {
            $this->commands([UnblockIpCommand::class]);
        }

        $this->callAfterResolving(HttpKernel::class, static function (HttpKernel $kernel): void {
            if ($kernel instanceof Kernel) {
                $kernel->addToMiddlewarePriorityAfter(
                    [StartSession::class, AuthenticatesRequests::class],
                    ProtectRequests::class,
                );
            }
        });
    }
}
