<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Tests;

use Crocodile2024\WAF\WAFServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    protected function getPackageProviders($app): array
    {
        return [WAFServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);
        $app['config']->set('waf.pepper', 'test-pepper-0123456789abcdef');
        $app['config']->set('waf.redis.prefix', 'waftest:');
        $app['config']->set('waf.redis.connection', 'waf');
        $app['config']->set('cache.default', 'array');

        $app['config']->set('database.redis.client', 'phpredis');
        $app['config']->set('database.redis.waf', [
            'host' => env('REDIS_HOST', '127.0.0.1'),
            'port' => (int) env('REDIS_PORT', 6379),
            'database' => (int) env('WAF_REDIS_DB', 15),
            'prefix' => '',
        ]);
    }

    protected function setUp(): void
    {
        parent::setUp();

        \Crocodile2024\WAF\Services\RuleRegistry::resetCache();
        \Crocodile2024\WAF\Services\IpListService::resetCache();
        $this->app->make(\Crocodile2024\WAF\Services\SettingsRepository::class)->refresh();

        try {
            $this->app->make(\Crocodile2024\WAF\Support\RedisStore::class)->flushPrefix();
        } catch (\Throwable) {
            // Redis optional für reine Unit-Tests.
        }
    }

    protected function defineDatabaseMigrations(): void
    {
        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
    }

    protected function usesRealRedis(): bool
    {
        return (bool) env('WAF_TEST_REDIS', false);
    }
}
