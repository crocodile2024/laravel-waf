<?php

declare(strict_types=1);

use Crocodile2024\WAF\Engine\RequestContext;
use Crocodile2024\WAF\Engine\Rules\RuleMatch;
use Crocodile2024\WAF\Models\Ban;
use Crocodile2024\WAF\Models\Event;
use Crocodile2024\WAF\Models\LearningHit;
use Crocodile2024\WAF\Models\StatHourly;
use Crocodile2024\WAF\Services\BanService;
use Crocodile2024\WAF\Services\EventFlusher;
use Crocodile2024\WAF\Services\EventRecorder;
use Crocodile2024\WAF\Services\LearningService;
use Crocodile2024\WAF\Services\RateLimitService;
use Crocodile2024\WAF\Services\ReputationService;
use Crocodile2024\WAF\Services\RuleImporter;

it('rate limiter blocks after the limit with gcra', function () {
    $rl = app(RateLimitService::class);
    $allowed = 0;
    for ($i = 0; $i < 10; $i++) {
        if ($rl->gcra('test:key', 5, 60, 0)->allowed) {
            $allowed++;
        }
    }
    expect($allowed)->toBeLessThanOrEqual(6)->toBeGreaterThanOrEqual(4);
});

it('ban escalation increases duration', function () {
    config()->set('waf.bans.escalation', [15, 60, 1440]);
    $bans = app(BanService::class);
    $first = $bans->ban('198.51.100.7', null, 'test');
    $bans->unban('198.51.100.7');
    $second = $bans->ban('198.51.100.7', null, 'test');
    expect($first->level)->toBe(1)->and($second->level)->toBe(2);
});

it('reputation decays over time', function () {
    $rep = app(ReputationService::class);
    $rep->add('198.51.100.8', 40);
    expect($rep->score('198.51.100.8'))->toBeGreaterThan(39.0)->toBeLessThanOrEqual(40.0);
});

it('sync loads active bans from database into redis', function () {
    $bans = app(BanService::class);
    Ban::query()->create([
        'ip_key' => '198.51.100.9', 'ip_hash' => str_repeat('a', 64),
        'reason' => 'db', 'level' => 1, 'banned_until' => now()->addHour(), 'source' => 'manual',
    ]);
    // Redis ist leer (kein ban:-Schlüssel) → nach Sync vorhanden
    expect($bans->isBanned('198.51.100.9'))->toBeFalse();
    $count = $bans->syncFromDatabase();
    expect($count)->toBe(1)->and($bans->isBanned('198.51.100.9'))->toBeTrue();
});

it('event flush writes queue to database and aggregates stats', function () {
    app(RuleImporter::class)->importCorePack();
    $recorder = app(EventRecorder::class);
    $ctx = RequestContext::make(['ip' => '203.0.113.50', 'path' => '/x', 'method' => 'GET']);
    $match = new RuleMatch('WAF-SQLI-001', 'UNION', 'critical', 5, 'query.q', 'q', "' UNION SELECT", 0, ['sqli']);
    $recorder->record($ctx, 'blocked', 'block', 403, 5, [$match]);

    $written = app(EventFlusher::class)->flush();
    expect($written)->toBe(1);
    expect(Event::query()->count())->toBe(1);
    expect(StatHourly::query()->where('outcome', 'blocked')->exists())->toBeTrue();
});

it('redacts sensitive parameters in stored snippets', function () {
    $recorder = app(EventRecorder::class);
    $ctx = RequestContext::make(['ip' => '203.0.113.51']);
    $match = new RuleMatch('WAF-TEST', 'T', 'critical', 5, 'body.password', 'password', 'supersecret123', 0, []);
    $recorder->record($ctx, 'logged', 'detect', null, 5, [$match]);
    app(EventFlusher::class)->flush();

    $event = Event::query()->first();
    expect($event->matches[0]['snippet'])->toBe('[GESCHWÄRZT]');
});

it('learning mode groups hits by rule, route and parameter', function () {
    $learning = app(LearningService::class);
    $ctx = RequestContext::make(['ip' => '203.0.113.52', 'path' => '/kontakt']);
    $match = new RuleMatch('WAF-XSS-001', 'XSS', 'critical', 5, 'body.msg', 'msg', '<script>', 0, ['xss']);
    $learning->collect($ctx, [$match]);
    $learning->collect($ctx, [$match]);

    $hit = LearningHit::query()->where('rule_code', 'WAF-XSS-001')->first();
    expect($hit)->not->toBeNull()->and($hit->hit_count)->toBe(2)->and($hit->distinct_ip_count)->toBe(1)
        ->and($hit->isSuspicious())->toBeTrue();
});
