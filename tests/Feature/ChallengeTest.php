<?php

declare(strict_types=1);

use Crocodile2024\WAF\Engine\RequestContext;
use Crocodile2024\WAF\Services\ChallengeService;

it('issues and verifies a proof of work', function () {
    config()->set('waf.challenge.pow_difficulty', 10);
    $service = app(ChallengeService::class);
    $ctx = RequestContext::make(['ip' => '203.0.113.9', 'headers' => ['user-agent' => 'Mozilla/5.0']]);

    $task = $service->issue($ctx);
    $solution = solvePow($task['nonce'], $task['difficulty']);

    expect($service->verify($ctx, $task['nonce'], $solution))->toBeTrue();
});

it('rejects an invalid solution', function () {
    config()->set('waf.challenge.pow_difficulty', 12);
    $service = app(ChallengeService::class);
    $ctx = RequestContext::make(['ip' => '203.0.113.9', 'headers' => ['user-agent' => 'UA']]);
    $task = $service->issue($ctx);

    expect($service->verify($ctx, $task['nonce'], '0'))->toBeFalse();
});

it('issues a pass cookie bound to ip and ua that validates', function () {
    $service = app(ChallengeService::class);
    $ctx = RequestContext::make(['ip' => '203.0.113.9', 'headers' => ['user-agent' => 'UA-1']]);
    $pass = $service->issuePass($ctx);

    $withCookie = RequestContext::make(['ip' => '203.0.113.9', 'headers' => ['user-agent' => 'UA-1'], 'cookies' => [ChallengeService::COOKIE => $pass]]);
    $otherUa = RequestContext::make(['ip' => '203.0.113.9', 'headers' => ['user-agent' => 'UA-2'], 'cookies' => [ChallengeService::COOKIE => $pass]]);

    expect($service->hasValidPass($withCookie))->toBeTrue()
        ->and($service->hasValidPass($otherUa))->toBeFalse();
});

it('solves the challenge via http and sets the pass cookie', function () {
    config()->set('waf.challenge.pow_difficulty', 8);
    $service = app(ChallengeService::class);
    $ctx = RequestContext::make(['ip' => '127.0.0.1', 'headers' => ['user-agent' => 'Symfony']]);
    // Reproduzierbare Challenge: gleiche Bindung wie der HTTP-Testclient
    $task = $service->issue($ctx);
    $solution = solvePow($task['nonce'], $task['difficulty']);

    $this->post('waf/challenge', ['nonce' => $task['nonce'], 'solution' => $solution, 'target' => '/dashboard'])
        ->assertRedirect('/dashboard')
        ->assertCookie(ChallengeService::COOKIE);
});

function solvePow(string $nonce, int $difficulty): string
{
    $s = 0;
    while (true) {
        $hash = hash('sha256', $nonce.'|'.$s, true);
        if (leadingZeroBits($hash) >= $difficulty) {
            return (string) $s;
        }
        $s++;
    }
}

function leadingZeroBits(string $bin): int
{
    $bits = 0;
    foreach (str_split($bin) as $c) {
        $b = ord($c);
        if ($b === 0) {
            $bits += 8;

            continue;
        }
        for ($m = 0x80; $m > 0; $m >>= 1) {
            if (($b & $m) === 0) {
                $bits++;
            } else {
                return $bits;
            }
        }
    }

    return $bits;
}
