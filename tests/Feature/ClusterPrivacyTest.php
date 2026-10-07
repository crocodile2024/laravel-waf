<?php

declare(strict_types=1);

use Crocodile2024\WAF\Models\Event;
use Crocodile2024\WAF\Models\Rule;
use Crocodile2024\WAF\Services\PruneService;
use Crocodile2024\WAF\Services\RuleImporter;
use Crocodile2024\WAF\Services\RuleRegistry;

it('reloads rules when the version changes', function () {
    app(RuleImporter::class)->importCorePack();
    $registry = app(RuleRegistry::class);
    $first = $registry->recompile();
    $countBefore = count($first->request);

    // Neue Regel + Recompile erhöht die Version und verteilt den Plan
    Rule::query()->create([
        'code' => 'WAF-CLUSTER-001', 'source' => 'custom', 'name' => 'Cluster', 'severity' => 'critical',
        'paranoia_level' => 1, 'priority' => 50, 'phase' => 'request',
        'conditions' => ['match' => 'any', 'items' => [['target' => 'query.q', 'operator' => 'contains', 'value' => 'x']]],
        'transforms' => [], 'action' => ['type' => 'block'], 'tags' => [], 'is_active' => true,
    ]);
    RuleRegistry::resetCache();
    $second = $registry->recompile();

    expect($second->version)->toBeGreaterThan($first->version)
        ->and(count($second->request))->toBe($countBefore + 1);

    // Simuliert einen zweiten Knoten: frischer In-Process-Cache lädt denselben Plan aus Redis
    RuleRegistry::resetCache();
    $reloaded = $registry->current();
    expect($reloaded->version)->toBe($second->version)
        ->and(count($reloaded->request))->toBe($countBefore + 1);
});

it('anonymizes old events and deletes expired data', function () {
    config()->set('waf.privacy.anonymize_after_days', 7);
    config()->set('waf.privacy.retention_days', 30);

    $old = Event::query()->create([
        'id' => (string) Str::ulid(), 'occurred_at' => now()->subDays(10), 'ip' => '203.0.113.200',
        'ip_hash' => str_repeat('b', 64), 'method' => 'GET', 'path' => '/x', 'mode' => 'block',
        'outcome' => 'blocked', 'score' => 5, 'user_agent' => 'secret-agent',
    ]);
    $veryOld = Event::query()->create([
        'id' => (string) Str::ulid(), 'occurred_at' => now()->subDays(40), 'ip' => '203.0.113.201',
        'ip_hash' => str_repeat('c', 64), 'method' => 'GET', 'path' => '/y', 'mode' => 'block',
        'outcome' => 'blocked', 'score' => 5,
    ]);

    $result = app(PruneService::class)->run();

    $old->refresh();
    expect($old->ip)->toBe('203.0.113.0')->and($old->user_agent)->toBeNull()->and($old->anonymized_at)->not->toBeNull();
    expect(Event::query()->whereKey($veryOld->id)->exists())->toBeFalse();
    expect($result['anonymized'])->toBeGreaterThanOrEqual(1);
});
