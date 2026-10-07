<?php

declare(strict_types=1);

use Crocodile2024\WAF\Models\Rule;
use Crocodile2024\WAF\Services\RuleImporter;
use Crocodile2024\WAF\Services\RuleRegistry;
use Illuminate\Support\Facades\Route;

beforeEach(function () {
    config()->set('waf.enabled', true);
    config()->set('waf.mode', 'block');
    config()->set('waf.paranoia_level', 2);
    app(RuleImporter::class)->importCorePack();
    app(RuleRegistry::class)->recompile();

    Route::middleware('web')->group(function () {
        Route::get('/test-endpoint', fn () => 'ok')->name('test.endpoint');
        Route::post('/test-endpoint', fn () => 'ok');
    });
});

it('allows clean requests', function () {
    $this->get('/test-endpoint?q=hallo+welt')->assertOk()->assertSee('ok');
});

it('blocks sql injection in block mode', function () {
    $response = $this->get('/test-endpoint?'.http_build_query(['q' => "' OR 1=1--"]));
    $response->assertStatus(403);
    $response->assertSee('blockiert', false);
});

it('blocks xss payloads', function () {
    $this->get('/test-endpoint?'.http_build_query(['name' => '<script>alert(1)</script>']))->assertStatus(403);
});

it('returns json error for api requests', function () {
    $this->postJson('/test-endpoint', ['q' => "' UNION SELECT password FROM users--"])
        ->assertStatus(403)
        ->assertJsonStructure(['error', 'incident_id']);
});

it('does not block in detect mode', function () {
    config()->set('waf.mode', 'detect');
    $this->get('/test-endpoint?'.http_build_query(['q' => "' OR 1=1--"]))->assertOk();
});

it('respects allowlist', function () {
    app(\Crocodile2024\WAF\Services\IpListService::class)->add('allow', '127.0.0.1', ['comment' => 'test']);
    $this->get('/test-endpoint?'.http_build_query(['q' => "' OR 1=1--"]))->assertOk();
});

it('blocks denylisted ips', function () {
    app(\Crocodile2024\WAF\Services\IpListService::class)->add('deny', '127.0.0.1', ['comment' => 'test']);
    $this->get('/test-endpoint')->assertStatus(403);
});

it('sets security headers', function () {
    $response = $this->get('/test-endpoint');
    $response->assertHeader('X-Content-Type-Options', 'nosniff');
    $response->assertHeader('X-Frame-Options', 'SAMEORIGIN');
});

it('bans ip via facade and blocks it', function () {
    \Crocodile2024\WAF\Facades\WAF::ban('127.0.0.1', 60, 'test');
    expect(\Crocodile2024\WAF\Facades\WAF::isBanned('127.0.0.1'))->toBeTrue();
    $this->get('/test-endpoint')->assertStatus(403);
});
