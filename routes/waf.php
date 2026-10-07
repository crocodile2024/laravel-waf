<?php

declare(strict_types=1);

use Crocodile2024\WAF\Http\Controllers\AuditController;
use Crocodile2024\WAF\Http\Controllers\BanController;
use Crocodile2024\WAF\Http\Controllers\ChallengeController;
use Crocodile2024\WAF\Http\Controllers\CspReportController;
use Crocodile2024\WAF\Http\Controllers\DashboardController;
use Crocodile2024\WAF\Http\Controllers\EventController;
use Crocodile2024\WAF\Http\Controllers\ExceptionController;
use Crocodile2024\WAF\Http\Controllers\IpListController;
use Crocodile2024\WAF\Http\Controllers\RuleController;
use Crocodile2024\WAF\Http\Controllers\SettingController;
use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken;
use Illuminate\Support\Facades\Route;

// Challenge- und CSP-Report-Routen (immer aktiv, von der WAF ausgenommen).
Route::middleware('web')->group(function (): void {
    Route::get('waf/challenge', [ChallengeController::class, 'show'])->name('waf.challenge.show');
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
