<?php

declare(strict_types=1);

use Crocodile2024\WAF\Models\AuditLog;
use Crocodile2024\WAF\Models\Rule;
use Crocodile2024\WAF\Services\RuleImporter;
use Illuminate\Support\Facades\Gate;

beforeEach(function () {
    config()->set('waf.mode', 'off');
    app(RuleImporter::class)->importCorePack();
});

it('denies UI access without the gate', function () {
    $this->get('admin/waf')->assertForbidden();
});

it('allows UI access when the gate passes', function () {
    Gate::define('viewWAF', fn ($u = null) => true);
    $this->get('admin/waf')->assertOk()->assertSee('Übersicht');
});

it('shows events page', function () {
    Gate::define('viewWAF', fn ($u = null) => true);
    $this->get('admin/waf/events')->assertOk()->assertSee('Ereignisse');
});

it('rejects rule creation without manage gate', function () {
    Gate::define('viewWAF', fn ($u = null) => true);
    Gate::define('manageWAF', fn ($u = null) => false);
    $this->post('admin/waf/rules', rulePayload())->assertForbidden();
});

it('creates a custom rule and writes an audit entry', function () {
    Gate::define('viewWAF', fn ($u = null) => true);
    Gate::define('manageWAF', fn ($u = null) => true);

    $this->post('admin/waf/rules', rulePayload())->assertRedirect();

    $rule = Rule::query()->where('code', 'WAF-CUSTOM-001')->first();
    expect($rule)->not->toBeNull()->and($rule->source)->toBe('custom');
    expect(AuditLog::query()->where('action', 'rule.create')->count())->toBe(1);
});

it('rejects a custom rule with a ReDoS regex', function () {
    Gate::define('viewWAF', fn ($u = null) => true);
    Gate::define('manageWAF', fn ($u = null) => true);

    $payload = rulePayload();
    $payload['conditions'] = json_encode(['match' => 'any', 'items' => [['target' => 'query.q', 'operator' => 'regex', 'value' => '(a+)+']]]);

    $this->from('admin/waf/rules/create')->post('admin/waf/rules', $payload)
        ->assertRedirect('admin/waf/rules/create')->assertSessionHasErrors('conditions');
    expect(Rule::query()->where('code', 'WAF-CUSTOM-001')->exists())->toBeFalse();
});

it('cannot edit core rules', function () {
    Gate::define('viewWAF', fn ($u = null) => true);
    Gate::define('manageWAF', fn ($u = null) => true);
    $core = Rule::query()->where('source', 'core')->first();

    $this->put('admin/waf/rules/'.$core->id, rulePayload(['code' => $core->code]))
        ->assertSessionHasErrors('rule');
});

it('runs the rule tester endpoint', function () {
    Gate::define('viewWAF', fn ($u = null) => true);
    $response = $this->postJson('admin/waf/rules/test', [
        'method' => 'GET',
        'path' => '/suche?q='.urlencode("' OR 1=1--"),
        'body' => '',
    ]);
    $response->assertOk()->assertJsonStructure(['result', 'score', 'matches', 'normalizations']);
    expect($response->json('result'))->toBe('blockiert');
});

function rulePayload(array $overrides = []): array
{
    return array_merge([
        'code' => 'WAF-CUSTOM-001',
        'name' => 'Testregel',
        'severity' => 'critical',
        'paranoia_level' => 1,
        'priority' => 100,
        'phase' => 'request',
        'is_active' => '1',
        'conditions' => json_encode(['match' => 'any', 'items' => [['target' => 'query.q', 'operator' => 'contains', 'value' => 'evil']]]),
        'action' => json_encode(['type' => 'block', 'status' => 403]),
    ], $overrides);
}
