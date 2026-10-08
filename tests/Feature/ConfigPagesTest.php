<?php

declare(strict_types=1);

use Crocodile2024\WAF\Models\InspectionProfile;
use Crocodile2024\WAF\Models\NotificationChannel;
use Crocodile2024\WAF\Models\ProfileAssignment;
use Crocodile2024\WAF\Models\RateLimitProfile;
use Crocodile2024\WAF\Services\ConfigManager;
use Illuminate\Support\Facades\Gate;

beforeEach(function () {
    config()->set('waf.mode', 'off');
    Gate::define('viewWAF', fn ($u = null) => true);
    Gate::define('manageWAF', fn ($u = null) => true);
});

it('renders all configuration pages', function () {
    foreach (['rate-limits', 'bots', 'geo', 'uploads', 'headers', 'headers?tab=reports', 'profiles', 'notifications'] as $page) {
        $this->get('admin/waf/'.$page)->assertOk();
    }
});

it('saves bot settings via ui', function () {
    $this->put('admin/waf/bots', [
        'challenge_type' => 'pow', 'pow_difficulty' => 20, 'pass_ttl_hours' => 6,
        'verify_search_engines' => '1', 'trap_paths' => "wp-login.php\nxmlrpc.php",
    ])->assertRedirect();
    $c = app(ConfigManager::class);
    expect($c->get('challenge.pow_difficulty'))->toBe(20)
        ->and($c->get('bots.trap_paths'))->toBe(['wp-login.php', 'xmlrpc.php']);
});

it('saves geo denylist as iso codes', function () {
    $this->put('admin/waf/geo', ['denied_countries' => 'ru, kp cn', 'allowed_countries' => '', 'denied_asns' => '12345'])
        ->assertRedirect();
    expect(app(ConfigManager::class)->get('geoip.denied_countries'))->toBe(['RU', 'KP', 'CN'])
        ->and(app(ConfigManager::class)->get('geoip.denied_asns'))->toBe([12345]);
});

it('creates a rate limit profile and assignment', function () {
    $this->post('admin/waf/rate-limits', [
        'name' => 'login', 'key_type' => 'ip', 'limit' => 5, 'window_seconds' => 60, 'action_type' => 'challenge',
    ])->assertRedirect();
    $profile = RateLimitProfile::query()->where('name', 'login')->first();
    expect($profile)->not->toBeNull()->and($profile->action['type'])->toBe('challenge');

    $this->post('admin/waf/rate-limits/assign', [
        'profile_id' => $profile->id, 'match_type' => 'route_name', 'match_value' => 'login',
    ])->assertRedirect();
    expect(ProfileAssignment::query()->where('profile_id', $profile->id)->exists())->toBeTrue();
});

it('creates a webhook notification channel', function () {
    $this->post('admin/waf/notifications', [
        'type' => 'webhook', 'target' => 'https://example.de/hook', 'secret' => 's3cret',
        'events' => ['ban', 'critical_hit'], 'min_severity' => 'warning', 'digest' => 'instant',
    ])->assertRedirect();
    $channel = NotificationChannel::query()->first();
    expect($channel)->not->toBeNull()->and($channel->events)->toContain('ban');
});

it('rejects an invalid webhook url', function () {
    $this->post('admin/waf/notifications', [
        'type' => 'webhook', 'target' => 'not-a-url', 'events' => ['ban'], 'min_severity' => 'warning', 'digest' => 'instant',
    ])->assertSessionHasErrors('target');
});

it('saves an inspection profile', function () {
    $this->post('admin/waf/profiles', ['name' => 'admin', 'paranoia_level' => 3, 'allowed_countries' => 'DE AT CH'])
        ->assertRedirect();
    $p = InspectionProfile::query()->where('name', 'admin')->first();
    expect($p)->not->toBeNull()->and($p->allowed_countries)->toBe(['DE', 'AT', 'CH']);
});
