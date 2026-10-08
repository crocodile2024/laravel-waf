<?php

declare(strict_types=1);

use Crocodile2024\WAF\Engine\RequestContext;
use Crocodile2024\WAF\Services\CaptchaService;
use Crocodile2024\WAF\Services\ChallengeService;
use Crocodile2024\WAF\Support\RedisStore;

it('issues, renders and verifies a captcha', function () {
    $captcha = app(CaptchaService::class);
    expect($captcha->available())->toBeTrue();

    $ctx = RequestContext::make(['ip' => '203.0.113.42', 'headers' => ['user-agent' => 'Mozilla']]);
    $token = $captcha->issue($ctx);

    // Erwarteten Code aus Redis lesen (nur im Test), um die Verifikation zu prüfen
    $stored = app(RedisStore::class)->get('cap:'.$token);
    $code = explode('|', (string) $stored, 2)[0];

    $png = $captcha->render($token);
    expect($png)->toStartWith("\x89PNG");

    expect($captcha->verify($ctx, $token, strtolower($code)))->toBeTrue();
});

it('rejects a wrong captcha answer and binds to ip+ua', function () {
    $captcha = app(CaptchaService::class);
    $ctx = RequestContext::make(['ip' => '203.0.113.43', 'headers' => ['user-agent' => 'UA-1']]);
    $token = $captcha->issue($ctx);
    $code = explode('|', (string) app(RedisStore::class)->get('cap:'.$token), 2)[0];

    $other = RequestContext::make(['ip' => '203.0.113.43', 'headers' => ['user-agent' => 'UA-2']]);
    expect($captcha->verify($other, $token, $code))->toBeFalse(); // falsche Bindung
    expect($captcha->verify($ctx, $token, 'ZZZZZ'))->toBeFalse();  // falsche Antwort
});

it('serves the captcha page and image in captcha mode', function () {
    config()->set('waf.challenge.type', 'captcha');
    config()->set('waf.mode', 'block');

    $page = $this->get('waf/challenge/captcha?target=/konto');
    $page->assertStatus(429)->assertSee('name="answer"', false);

    // Token aus dem Formular ziehen und Bild abrufen
    preg_match('/name="token" value="([^"]+)"/', $page->getContent(), $m);
    expect($m[1] ?? null)->not->toBeNull();
    $this->get('waf/challenge/captcha.png?token='.$m[1])
        ->assertOk()->assertHeader('Content-Type', 'image/png');
});

it('solves a captcha via http and sets the pass cookie', function () {
    $captcha = app(CaptchaService::class);
    $ctx = RequestContext::make(['ip' => '127.0.0.1', 'headers' => ['user-agent' => 'Symfony']]);
    $token = $captcha->issue($ctx);
    $code = explode('|', (string) app(RedisStore::class)->get('cap:'.$token), 2)[0];

    $this->post('waf/challenge', ['mode' => 'captcha', 'token' => $token, 'answer' => $code, 'target' => '/dashboard'])
        ->assertRedirect('/dashboard')
        ->assertCookie(ChallengeService::COOKIE);
});
