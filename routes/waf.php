<?php

declare(strict_types=1);

use Crocodile2024\WAF\Http\Controllers\AuditController;
use Crocodile2024\WAF\Http\Controllers\BanController;
use Crocodile2024\WAF\Http\Controllers\ChallengeController;
use Crocodile2024\WAF\Http\Controllers\ConfigController;
use Crocodile2024\WAF\Http\Controllers\CspReportController;
use Crocodile2024\WAF\Http\Controllers\DashboardController;
use Crocodile2024\WAF\Http\Controllers\EventController;
use Crocodile2024\WAF\Http\Controllers\ExceptionController;
use Crocodile2024\WAF\Http\Controllers\IpListController;
use Crocodile2024\WAF\Http\Controllers\NotificationController;
use Crocodile2024\WAF\Http\Controllers\ProfileController;
use Crocodile2024\WAF\Http\Controllers\RateLimitController;
use Crocodile2024\WAF\Http\Controllers\RuleController;
use Crocodile2024\WAF\Http\Controllers\SettingController;
use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken;
use Illuminate\Support\Facades\Route;

// Challenge- und CSP-Report-Routen (immer aktiv, von der WAF ausgenommen).
Route::middleware('web')->group(function (): void {
    Route::get('waf/challenge', [ChallengeController::class, 'show'])->name('waf.challenge.show');
    Route::get('waf/challenge/captcha', [ChallengeController::class, 'captcha'])->name('waf.challenge.captcha');
    Route::get('waf/challenge/captcha.png', [ChallengeController::class, 'captchaImage'])->name('waf.challenge.captcha-image');
    Route::post('waf/challenge', [ChallengeController::class, 'solve'])->name('waf.challenge.solve');
    Route::post('waf/csp-report', [CspReportController::class, 'store'])
        ->name('waf.csp-report')->withoutMiddleware(ValidateCsrfToken::class);
});

// Verwaltungsoberfläche
if (config('waf.ui.enabled', true)) {
    Route::domain((string) config('waf.ui.domain') ?: null)
        ->prefix((string) config('waf.ui.path', 'admin/waf'))
        ->middleware(array_merge((array) config('waf.ui.middleware', ['web', 'auth']), ['can:'.config('waf.ui.gate', 'viewWAF')]))
        ->name('waf.ui.')
        ->group(function (): void {
            Route::get('/', [DashboardController::class, 'index'])->name('dashboard');
            Route::get('/api/dashboard', [DashboardController::class, 'data'])->name('dashboard.data');

            Route::get('/events', [EventController::class, 'index'])->name('events.index');
            Route::get('/events/stream', [EventController::class, 'stream'])->name('events.stream');
            Route::get('/events/export', [EventController::class, 'export'])->name('events.export');
            Route::get('/events/{event}', [EventController::class, 'show'])->name('events.show');

            Route::get('/exceptions', [ExceptionController::class, 'index'])->name('exceptions.index');
            Route::post('/exceptions', [ExceptionController::class, 'store'])->name('exceptions.store');
            Route::delete('/exceptions/{exception}', [ExceptionController::class, 'destroy'])->name('exceptions.destroy');
            Route::post('/exceptions/suggestions/{hit}/accept', [ExceptionController::class, 'acceptSuggestion'])->name('exceptions.accept');
            Route::post('/exceptions/suggestions/{hit}/dismiss', [ExceptionController::class, 'dismissSuggestion'])->name('exceptions.dismiss');

            Route::get('/ip-lists', [IpListController::class, 'index'])->name('ip-lists.index');
            Route::post('/ip-lists', [IpListController::class, 'store'])->name('ip-lists.store');
            Route::post('/ip-lists/import', [IpListController::class, 'import'])->name('ip-lists.import');
            Route::delete('/ip-lists/{ipEntry}', [IpListController::class, 'destroy'])->name('ip-lists.destroy');

            Route::get('/bans', [BanController::class, 'index'])->name('bans.index');
            Route::post('/bans', [BanController::class, 'store'])->name('bans.store');
            Route::delete('/bans', [BanController::class, 'destroy'])->name('bans.destroy');

            Route::get('/audit', [AuditController::class, 'index'])->name('audit.index');

            Route::get('/rate-limits', [RateLimitController::class, 'index'])->name('rate-limits.index');
            Route::post('/rate-limits', [RateLimitController::class, 'store'])->name('rate-limits.store');
            Route::delete('/rate-limits/{profile}', [RateLimitController::class, 'destroy'])->name('rate-limits.destroy');
            Route::post('/rate-limits/assign', [RateLimitController::class, 'assign'])->name('rate-limits.assign');
            Route::delete('/rate-limits/assign/{assignment}', [RateLimitController::class, 'unassign'])->name('rate-limits.unassign');

            Route::get('/profiles', [ProfileController::class, 'index'])->name('profiles.index');
            Route::post('/profiles', [ProfileController::class, 'store'])->name('profiles.store');
            Route::delete('/profiles/{profile}', [ProfileController::class, 'destroy'])->name('profiles.destroy');
            Route::post('/profiles/assign', [ProfileController::class, 'assign'])->name('profiles.assign');
            Route::delete('/profiles/assign/{assignment}', [ProfileController::class, 'unassign'])->name('profiles.unassign');

            Route::get('/bots', [ConfigController::class, 'bots'])->name('bots.index');
            Route::put('/bots', [ConfigController::class, 'updateBots'])->name('bots.update');
            Route::get('/geo', [ConfigController::class, 'geo'])->name('geo.index');
            Route::put('/geo', [ConfigController::class, 'updateGeo'])->name('geo.update');
            Route::get('/uploads', [ConfigController::class, 'uploads'])->name('uploads.index');
            Route::put('/uploads', [ConfigController::class, 'updateUploads'])->name('uploads.update');
            Route::get('/headers', [ConfigController::class, 'headers'])->name('headers.index');
            Route::put('/headers', [ConfigController::class, 'updateHeaders'])->name('headers.update');

            Route::get('/notifications', [NotificationController::class, 'index'])->name('notifications.index');
            Route::post('/notifications', [NotificationController::class, 'store'])->name('notifications.store');
            Route::delete('/notifications/{channel}', [NotificationController::class, 'destroy'])->name('notifications.destroy');
            Route::post('/notifications/{channel}/test', [NotificationController::class, 'test'])->name('notifications.test');

            Route::get('/settings', [SettingController::class, 'index'])->name('settings.index');
            Route::put('/settings', [SettingController::class, 'update'])->name('settings.update');

            Route::get('/rules', [RuleController::class, 'index'])->name('rules.index');
            Route::get('/rules/create', [RuleController::class, 'create'])->name('rules.create');
            Route::post('/rules', [RuleController::class, 'store'])->name('rules.store');
            Route::get('/rules/{rule}/edit', [RuleController::class, 'edit'])->name('rules.edit');
            Route::put('/rules/{rule}', [RuleController::class, 'update'])->name('rules.update');
            Route::delete('/rules/{rule}', [RuleController::class, 'destroy'])->name('rules.destroy');
            Route::post('/rules/{rule}/toggle', [RuleController::class, 'toggle'])->name('rules.toggle');
            Route::post('/rules/test', [RuleController::class, 'test'])->name('rules.test');
        });
}
