<?php

declare(strict_types=1);

use Crocodile2024\WAF\Http\Controllers\ChallengeController;
use Crocodile2024\WAF\Http\Controllers\CspReportController;
use Crocodile2024\WAF\Http\Controllers\DashboardController;
use Crocodile2024\WAF\Http\Controllers\EventController;
use Crocodile2024\WAF\Http\Controllers\RuleController;
use Illuminate\Support\Facades\Route;

// Challenge- und CSP-Report-Routen (immer aktiv, von der WAF ausgenommen).
Route::middleware('web')->group(function (): void {
    Route::get('waf/challenge', [ChallengeController::class, 'show'])->name('waf.challenge.show');
    Route::post('waf/challenge', [ChallengeController::class, 'solve'])->name('waf.challenge.solve');
    Route::post('waf/csp-report', [CspReportController::class, 'store'])
        ->name('waf.csp-report')->withoutMiddleware(\Illuminate\Foundation\Http\Middleware\ValidateCsrfToken::class);
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
