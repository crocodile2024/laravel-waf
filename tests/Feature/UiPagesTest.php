<?php

declare(strict_types=1);

use Crocodile2024\WAF\Models\Ban;
use Crocodile2024\WAF\Models\IpEntry;
use Crocodile2024\WAF\Models\WafException;
use Crocodile2024\WAF\Services\ConfigManager;
use Crocodile2024\WAF\Services\IpListService;
use Illuminate\Support\Facades\Gate;

beforeEach(function () {
    config()->set('waf.mode', 'off');
    Gate::define('viewWAF', fn ($u = null) => true);
    Gate::define('manageWAF', fn ($u = null) => true);
});

it('renders all operational pages', function () {
    foreach (['exceptions', 'ip-lists', 'bans', 'audit', 'settings'] as $page) {
        $this->get('admin/waf/'.$page)->assertOk();
    }
});

it('adds and removes an ip list entry', function () {
    $this->post('admin/waf/ip-lists', ['list' => 'deny', 'cidr' => '198.51.100.0/24', 'confirm_self' => '1'])
        ->assertRedirect();
    $entry = IpEntry::query()->where('cidr', '198.51.100.0/24')->first();
    expect($entry)->not->toBeNull()->and($entry->list)->toBe('deny');
    expect(app(IpListService::class)->isDenied('198.51.100.5'))->toBeTrue();

    $this->delete('admin/waf/ip-lists/'.$entry->id)->assertRedirect();
    expect(IpEntry::query()->whereKey($entry->id)->exists())->toBeFalse();
});

it('warns when denylisting own ip without confirmation', function () {
    $this->post('admin/waf/ip-lists', ['list' => 'deny', 'cidr' => '127.0.0.1'])
        ->assertSessionHasErrors('cidr');
    expect(IpEntry::query()->where('cidr', '127.0.0.1')->exists())->toBeFalse();
});

it('creates and lifts a ban via ui', function () {
    $this->post('admin/waf/bans', ['ip' => '203.0.113.90', 'reason' => 'test'])->assertRedirect();
    expect(Ban::query()->where('ip_key', '203.0.113.90')->active()->exists())->toBeTrue();
    $this->delete('admin/waf/bans', ['single' => '203.0.113.90'])->assertRedirect();
    expect(Ban::query()->where('ip_key', '203.0.113.90')->active()->exists())->toBeFalse();
});

it('creates an exception', function () {
    $this->post('admin/waf/exceptions', [
        'rule_code' => 'WAF-SQLI-002', 'scope_type' => 'path_pattern', 'scope_value' => '/suche',
    ])->assertRedirect();
    expect(WafException::query()->where('rule_code', 'WAF-SQLI-002')->exists())->toBeTrue();
});

it('requires BESTÄTIGEN to switch mode to off', function () {
    $payload = [
        'mode' => 'off', 'paranoia_level' => 1, 'inbound_threshold' => 5,
        'reputation_half_life_minutes' => 60, 'reputation_ban_threshold' => 50,
        'anonymize_after_days' => 7, 'retention_days' => 30,
    ];
    $this->put('admin/waf/settings', $payload)->assertSessionHasErrors('mode');
    $this->put('admin/waf/settings', $payload + ['confirm' => 'BESTÄTIGEN'])->assertRedirect();
    expect(app(ConfigManager::class)->mode()->value)->toBe('off');
});

it('writes audit entries that appear on the audit page', function () {
    $this->post('admin/waf/bans', ['ip' => '203.0.113.91'])->assertRedirect();
    $this->get('admin/waf/audit')->assertOk()->assertSee('ban.create');
});
