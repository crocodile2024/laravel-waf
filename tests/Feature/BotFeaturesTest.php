<?php

declare(strict_types=1);

use Crocodile2024\WAF\Engine\Decision;
use Crocodile2024\WAF\Engine\FirewallEngine;
use Crocodile2024\WAF\Engine\RequestContext;
use Crocodile2024\WAF\Engine\Stages\InspectionStage;
use Crocodile2024\WAF\Engine\Stages\StageRegistry;
use Crocodile2024\WAF\Engine\Stages\StageResult;
use Crocodile2024\WAF\Facades\WAF;
use Crocodile2024\WAF\Services\BanService;
use Crocodile2024\WAF\Services\BotService;
use Crocodile2024\WAF\Services\LoginGuard;
use Crocodile2024\WAF\Services\RuleImporter;
use Crocodile2024\WAF\Services\RuleRegistry;
use Illuminate\Auth\Events\Failed;
use Illuminate\Contracts\View\Factory;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\Event;

beforeEach(function () {
    config()->set('waf.mode', 'block');
    app(RuleImporter::class)->importCorePack();
    app(RuleRegistry::class)->recompile();
});

it('honeypot flags a filled decoy field', function () {
    $bots = app(BotService::class);
    $ctx = RequestContext::make([
        'method' => 'POST',
        'body' => ['name' => 'Bot', 'waf_hp' => 'ich bin ein bot', 'waf_hp_token' => $bots->honeypotToken()],
    ]);
    expect($bots->honeypotTriggered($ctx))->toBeTrue();
});

it('honeypot flags a too-fast submission', function () {
    config()->set('waf.bots.honeypot_min_seconds', 2);
    $bots = app(BotService::class);
    $token = $bots->honeypotToken(); // Zeitstempel = jetzt
    $ctx = RequestContext::make([
        'method' => 'POST',
        'body' => ['name' => 'Mensch', 'waf_hp' => '', 'waf_hp_token' => $token],
    ]);
    expect($bots->honeypotTriggered($ctx))->toBeTrue();
});

it('honeypot passes a legitimate slow submission', function () {
    config()->set('waf.bots.honeypot_min_seconds', 2);
    $bots = app(BotService::class);
    // Token mit Zeitstempel vor 10 s selbst signieren
    $ts = (string) (time() - 10);
    $token = $ts.'.'.hash_hmac('sha256', $ts, config('waf.pepper'));
    $ctx = RequestContext::make([
        'method' => 'POST',
        'body' => ['name' => 'Mensch', 'waf_hp' => '', 'waf_hp_token' => $token],
    ]);
    expect($bots->honeypotTriggered($ctx))->toBeFalse();
});

it('honeypot component renders hidden field and token', function () {
    app()->make(Factory::class);
    $html = Blade::render('<x-waf::honeypot />');
    expect($html)->toContain('name="waf_hp"')->toContain('name="waf_hp_token"');
});

it('login bruteforce bans after threshold', function () {
    config()->set('waf.rate_limit.login', ['enabled' => true, 'challenge_after' => 2, 'ban_after' => 3, 'window_seconds' => 900]);
    $guard = app(LoginGuard::class);
    $guard->recordFailure('198.51.100.30', 'opfer@example.de');
    $guard->recordFailure('198.51.100.30', 'opfer@example.de');
    expect($guard->shouldChallenge('198.51.100.30'))->toBeTrue();
    $guard->recordFailure('198.51.100.30', 'opfer@example.de');
    expect(app(BanService::class)->isBanned('198.51.100.30'))->toBeTrue();
});

it('failed auth event feeds the login guard', function () {
    config()->set('waf.rate_limit.login', ['enabled' => true, 'challenge_after' => 1, 'ban_after' => 99, 'window_seconds' => 900]);
    Event::dispatch(new Failed('web', null, ['email' => 'x@example.de', 'password' => 'secret']));
    // Request-IP im Test ist 127.0.0.1
    expect(app(LoginGuard::class)->shouldChallenge('127.0.0.1'))->toBeTrue();
});

it('executes a registered custom stage that blocks', function () {
    WAF::extend('deny-teapot', fn () => new class implements InspectionStage
    {
        public function handle(RequestContext $ctx): StageResult
        {
            return str_contains($ctx->path, '/teapot')
                ? StageResult::act('block', 'custom-teapot', status: 418)
                : StageResult::next();
        }
    });

    $ctx = RequestContext::make(['ip' => '203.0.113.77', 'path' => '/teapot']);
    $decision = app(FirewallEngine::class)->inspect($ctx);
    expect($decision->type)->toBe(Decision::BLOCK)->and($decision->status)->toBe(418);

    app(StageRegistry::class)->clear();
});
