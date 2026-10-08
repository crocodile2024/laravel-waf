<?php

declare(strict_types=1);

namespace Crocodile2024\WAF;

use Crocodile2024\WAF\Console\Commands;
use Crocodile2024\WAF\Engine\Inspector;
use Crocodile2024\WAF\Engine\Rules\RuleCompiler;
use Crocodile2024\WAF\Engine\Stages\StageRegistry;
use Crocodile2024\WAF\Http\Middleware\Firewall;
use Crocodile2024\WAF\Http\Middleware\ResponseInspector;
use Crocodile2024\WAF\Http\Middleware\SecurityHeaders;
use Crocodile2024\WAF\Services\ConfigManager;
use Crocodile2024\WAF\Services\SettingsRepository;
use Crocodile2024\WAF\Support\CspNonce;
use Crocodile2024\WAF\Support\Redactor;
use Crocodile2024\WAF\Support\RedisStore;
use Crocodile2024\WAF\View\Components\Honeypot;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\ServiceProvider;

class WAFServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/waf.php', 'waf');

        $this->app->singleton(RedisStore::class, function ($app): RedisStore {
            return new RedisStore(
                $app['redis'],
                (string) config('waf.redis.connection', 'default'),
                (string) config('waf.redis.prefix', 'waf:'),
            );
        });

        $this->app->singleton(SettingsRepository::class);
        $this->app->singleton(ConfigManager::class);
        $this->app->singleton(CspNonce::class);
        $this->app->scoped(Inspector::class);

        $this->app->singleton(Redactor::class, function (): Redactor {
            return new Redactor((array) config('waf.privacy.redact_keys', []));
        });

        $this->app->singleton(RuleCompiler::class);
        $this->app->singleton(StageRegistry::class);

        $this->app->singleton(WAFManager::class, function ($app): WAFManager {
            return new WAFManager(
                $app->make(Services\BanService::class),
                $app->make(Services\ReputationService::class),
                $app->make(Services\IpListService::class),
                $app->make(ConfigManager::class),
                $app->make(StageRegistry::class),
            );
        });
    }

    public function boot(): void
    {
        $this->registerMiddleware();
        $this->registerBladeDirectives();
        $this->registerGate();
        $this->loadResources();
        $this->registerPublishing();
        $this->registerCommands();
        $this->registerScheduler();
        $this->registerEventListeners();
        $this->loadRoutes();
    }

    private function registerEventListeners(): void
    {
        if (! config('waf.enabled', true) || ! config('waf.rate_limit.login.enabled', true)) {
            return;
        }
        /** @var Dispatcher $events */
        $events = $this->app->make('events');
        $events->listen(Failed::class, [Listeners\RecordFailedLogin::class, 'handleFailed']);
        $events->listen(Lockout::class, [Listeners\RecordFailedLogin::class, 'handleLockout']);
    }

    private function registerMiddleware(): void
    {
        /** @var Router $router */
        $router = $this->app->make('router');
        $router->aliasMiddleware('waf', Firewall::class);

        if (! config('waf.enabled', true)) {
            return;
        }

        /** @var Kernel $kernel */
        $kernel = $this->app->make(Kernel::class);
        // An den Anfang der globalen Kette (nach TrustProxies).
        $kernel->prependMiddleware(Firewall::class);

        if (config('waf.headers.enabled', true)) {
            $kernel->pushMiddleware(SecurityHeaders::class);
        }
        $kernel->pushMiddleware(ResponseInspector::class);
    }

    private function registerBladeDirectives(): void
    {
        Blade::directive('wafNonce', static fn (): string => "<?php echo 'nonce=\"'.e(waf_nonce()).'\"'; ?>");
    }

    private function registerGate(): void
    {
        // Paket definiert das Gate NICHT permissiv: Standard false (10.1).
        if (! Gate::has((string) config('waf.ui.gate', 'viewWAF'))) {
            Gate::define((string) config('waf.ui.gate', 'viewWAF'), static fn ($user = null): bool => false);
        }
    }

    private function loadResources(): void
    {
        $this->loadViewsFrom(__DIR__.'/../resources/views', 'waf');
        $this->loadTranslationsFrom(__DIR__.'/../resources/lang', 'waf');
        Blade::component('waf::honeypot', Honeypot::class);
    }

    private function loadRoutes(): void
    {
        if (file_exists($routes = __DIR__.'/../routes/waf.php')) {
            require $routes;
        }
    }

    private function registerPublishing(): void
    {
        if (! $this->app->runningInConsole()) {
            return;
        }
        $this->publishes([__DIR__.'/../config/waf.php' => config_path('waf.php')], 'waf-config');
        $this->publishes([__DIR__.'/../database/migrations' => database_path('migrations')], 'waf-migrations');
        $this->publishes([__DIR__.'/../resources/views' => resource_path('views/vendor/waf')], 'waf-views');
        $this->publishes([__DIR__.'/../dist' => public_path('vendor/waf')], 'waf-assets');
    }

    private function registerCommands(): void
    {
        if (! $this->app->runningInConsole()) {
            return;
        }
        $this->commands([
            Commands\InstallCommand::class,
            Commands\StatusCommand::class,
            Commands\ModeCommand::class,
            Commands\RulesImportCommand::class,
            Commands\RulesExportCommand::class,
            Commands\RulesTestCommand::class,
            Commands\RulesCompileCommand::class,
            Commands\BanCommand::class,
            Commands\UnbanCommand::class,
            Commands\AllowCommand::class,
            Commands\SyncCommand::class,
            Commands\EventsFlushCommand::class,
            Commands\PruneCommand::class,
            Commands\GeoIpUpdateCommand::class,
            Commands\BlocklistsUpdateCommand::class,
            Commands\NotifyDigestCommand::class,
            Commands\BenchmarkCommand::class,
        ]);
    }

    private function registerScheduler(): void
    {
        if (! config('waf.schedule.enabled', true)) {
            return;
        }
        $this->app->booted(function (): void {
            /** @var Schedule $schedule */
            $schedule = $this->app->make(Schedule::class);
            $schedule->command('waf:events:flush')->everyMinute()->onOneServer()->withoutOverlapping();
            $schedule->command('waf:prune')->dailyAt('03:15')->onOneServer()->withoutOverlapping();
            $schedule->command('waf:notify:digest hourly')->hourly()->onOneServer()->withoutOverlapping();
            $schedule->command('waf:notify:digest daily')->dailyAt('07:00')->onOneServer()->withoutOverlapping();
            if (config('waf.blocklists.enabled', false)) {
                $schedule->command('waf:blocklists:update')->everySixHours()->onOneServer()->withoutOverlapping();
            }
            if (config('waf.geoip.auto_update', false)) {
                $schedule->command('waf:geoip:update')->weekly()->onOneServer()->withoutOverlapping();
            }
        });
    }
}
