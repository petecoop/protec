<?php

declare(strict_types=1);

namespace Petecoop\Protec;

use Illuminate\Contracts\Auth\Middleware\AuthenticatesRequests;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Foundation\Http\Kernel;
use Illuminate\Routing\Router;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\ServiceProvider;
use Petecoop\Protec\Commands\UnblockIpCommand;
use Petecoop\Protec\Middleware\InspectRequests;
use Petecoop\Protec\Middleware\ProtectRequests;
use Throwable;

class ProtecServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/protec.php', 'protec');
    }

    public function boot(Router $router): void
    {
        $router->aliasMiddleware('protec', ProtectRequests::class);
        $this->registerPublishing();
        $this->registerMiddleware();
        $this->registerExceptionHandling();

        if ($this->app->runningInConsole()) {
            $this->commands([UnblockIpCommand::class]);
        }
    }

    protected function registerPublishing(): void
    {
        $this->publishes([__DIR__.'/../config/protec.php' => config_path('protec.php')], 'protec-config');
        $this->publishesMigrations([
            __DIR__.'/../database/migrations/create_protec_ip_blocks_table.php' => database_path(
                'migrations/create_protec_ip_blocks_table.php',
            ),
        ], 'protec-migrations');
    }

    protected function registerMiddleware(): void
    {
        $this->callAfterResolving(HttpKernel::class, static function (HttpKernel $kernel): void {
            if (! $kernel instanceof Kernel) {
                return;
            }

            $kernel->pushMiddleware(InspectRequests::class);
            $kernel->addToMiddlewarePriorityAfter(
                [StartSession::class, AuthenticatesRequests::class],
                ProtectRequests::class,
            );

            foreach (config('protec.middleware_groups', ['web', 'api']) as $group) {
                if (! array_key_exists($group, $kernel->getMiddlewareGroups())) {
                    continue;
                }

                $kernel->appendMiddlewareToGroup($group, ProtectRequests::class);
            }
        });
    }

    protected function registerExceptionHandling(): void
    {
        // Register before application reporting callbacks, without replacing the
        // handler or its final response callback (which may belong to the app).
        $configure = static function (object $handler): void {
            if (is_callable([$handler, 'dontReportWhen'])) {
                $handler->dontReportWhen(static function (Throwable $exception): bool {
                    $request = request();
                    // Also supports apps rendering a plain Symfony response,
                    // which cannot carry Laravel's exception property.
                    $request->attributes->set('protec.exception', $exception);

                    return app(Protec::class)->shouldIgnoreException($exception, $request);
                });
            }
        };

        $this->app->resolving(ExceptionHandler::class, $configure);

        if ($this->app->resolved(ExceptionHandler::class)) {
            $configure($this->app->make(ExceptionHandler::class));
        }
    }
}
