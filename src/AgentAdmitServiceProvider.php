<?php

namespace AgentAdmit;

use Illuminate\Support\ServiceProvider;

/**
 * Laravel service provider for AgentAdmit.
 *
 * Registers the introspection client, middleware, and config.
 *
 * Installation:
 *   composer require agentadmit/laravel
 *
 * Publish config:
 *   php artisan vendor:publish --tag=agentadmit-config
 *
 * Add middleware to routes:
 *   Route::middleware('agentadmit.scope:read:orders')->get('/api/orders', ...);
 */
class AgentAdmitServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/agentadmit.php', 'agentadmit');

        $this->app->singleton(IntrospectionClient::class, function ($app) {
            return new IntrospectionClient(config('agentadmit'));
        });
    }

    public function boot(): void
    {
        $this->publishes([
            __DIR__ . '/../config/agentadmit.php' => config_path('agentadmit.php'),
        ], 'agentadmit-config');

        // Register middleware
        $router = $this->app['router'];
        $router->aliasMiddleware('agentadmit.scope', Middleware\RequireScope::class);
        $router->aliasMiddleware('agentadmit.scope_if_agent', Middleware\RequireScopeIfAgent::class);
    }
}
