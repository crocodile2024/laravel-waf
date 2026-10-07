<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Http\Controllers;

use Crocodile2024\WAF\Models\CspReport;
use Crocodile2024\WAF\Services\AuditLogger;
use Crocodile2024\WAF\Services\ClamAvScanner;
use Crocodile2024\WAF\Services\ConfigManager;
use Crocodile2024\WAF\Services\GeoIpService;
use Crocodile2024\WAF\Services\SettingsRepository;
use Illuminate\Contracts\View\View;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;

/**
 * Konfigurations-Abschnitte, die über waf_settings persistiert werden
 * (Bot-Schutz, Geo/ASN, Uploads, Security-Header).
 */
class ConfigController extends Controller
{
    public function __construct(
        private readonly ConfigManager $config,
        private readonly SettingsRepository $settings,
        private readonly AuditLogger $audit,
        private readonly GeoIpService $geo,
        private readonly ClamAvScanner $clamav,
    ) {}

    public function bots(): View
    {
        return view('waf::pages.bots', ['title' => 'Bot-Schutz', 'config' => $this->config->all(), 'canManage' => Gate::allows('manageWAF')]);
    }

    public function updateBots(Request $request): RedirectResponse
    {
        $this->authorizeManage();
        $v = $request->validate([
            'challenge_type' => ['required', 'in:pow,captcha'],
            'pow_difficulty' => ['required', 'integer', 'between:8,26'],
            'pass_ttl_hours' => ['required', 'integer', 'min:1'],
            'verify_search_engines' => ['nullable', 'boolean'],
            'block_empty_user_agent' => ['nullable', 'boolean'],
            'trap_paths' => ['nullable', 'string', 'max:4096'],
        ]);
        $actor = $this->actor();
        $this->settings->set('challenge.type', $v['challenge_type'], $actor);
        $this->settings->set('challenge.pow_difficulty', $v['pow_difficulty'], $actor);
        $this->settings->set('challenge.pass_ttl_hours', $v['pass_ttl_hours'], $actor);
        $this->settings->set('bots.verify_search_engines', $request->boolean('verify_search_engines'), $actor);
        $this->settings->set('bots.block_empty_user_agent', $request->boolean('block_empty_user_agent'), $actor);
        $this->settings->set('bots.trap_paths', $this->lines($v['trap_paths'] ?? ''), $actor);
        $this->audit->log('settings.bots', 'config', 'bots');

        return back()->with('status', 'Bot-Schutz gespeichert.');
    }

    public function geo(): View
    {
        return view('waf::pages.geo', [
            'title' => 'Geo & ASN',
            'config' => $this->config->all(),
            'available' => $this->geo->available(),
            'ageDays' => $this->geo->databaseAgeDays(),
            'canManage' => Gate::allows('manageWAF'),
        ]);
    }

    public function updateGeo(Request $request): RedirectResponse
    {
        $this->authorizeManage();
        $v = $request->validate([
            'allowed_countries' => ['nullable', 'string', 'max:2048'],
            'denied_countries' => ['nullable', 'string', 'max:2048'],
            'denied_asns' => ['nullable', 'string', 'max:2048'],
        ]);
        $actor = $this->actor();
        $this->settings->set('geoip.allowed_countries', $this->countries($v['allowed_countries'] ?? ''), $actor);
        $this->settings->set('geoip.denied_countries', $this->countries($v['denied_countries'] ?? ''), $actor);
        $this->settings->set('geoip.denied_asns', array_map('intval', $this->lines($v['denied_asns'] ?? '')), $actor);
        $this->audit->log('settings.geo', 'config', 'geo');

        return back()->with('status', 'Geo/ASN-Einstellungen gespeichert.');
    }

    public function uploads(): View
    {
        return view('waf::pages.uploads', [
            'title' => 'Uploads',
            'config' => $this->config->all(),
            'clamavAvailable' => $this->config->get('clamav.enabled', false) ? $this->clamav->available() : null,
            'canManage' => Gate::allows('manageWAF'),
        ]);
    }

    public function updateUploads(Request $request): RedirectResponse
    {
        $this->authorizeManage();
        $v = $request->validate([
            'allowed_extensions' => ['nullable', 'string', 'max:2048'],
            'max_file_mb' => ['required', 'integer', 'min:1'],
            'max_files' => ['required', 'integer', 'min:1'],
            'max_compression_ratio' => ['required', 'integer', 'min:1'],
            'clamav_enabled' => ['nullable', 'boolean'],
        ]);
        $actor = $this->actor();
        $this->settings->set('uploads.allowed_extensions', array_map('strtolower', $this->lines((string) ($v['allowed_extensions'] ?? ''), ',')), $actor);
        $this->settings->set('uploads.max_file_bytes', $v['max_file_mb'] * 1024 * 1024, $actor);
        $this->settings->set('uploads.max_files', $v['max_files'], $actor);
        $this->settings->set('uploads.max_compression_ratio', $v['max_compression_ratio'], $actor);
        $this->settings->set('clamav.enabled', $request->boolean('clamav_enabled'), $actor);
        $this->audit->log('settings.uploads', 'config', 'uploads');

        return back()->with('status', 'Upload-Einstellungen gespeichert.');
    }

    public function headers(Request $request): View
    {
        return view('waf::pages.headers', [
            'title' => 'Security-Header',
            'config' => $this->config->all(),
            'tab' => $request->query('tab') === 'reports' ? 'reports' : 'headers',
            'reports' => CspReport::query()->orderByDesc('received_at')->orderByDesc('count')->limit(200)->get(),
            'canManage' => Gate::allows('manageWAF'),
        ]);
    }

    public function updateHeaders(Request $request): RedirectResponse
    {
        $this->authorizeManage();
        $v = $request->validate([
            'hsts_enabled' => ['nullable', 'boolean'],
            'hsts_max_age' => ['required', 'integer', 'min:0'],
            'x_frame_options' => ['required', 'in:DENY,SAMEORIGIN'],
            'referrer_policy' => ['required', 'string', 'max:64'],
            'csp_enabled' => ['nullable', 'boolean'],
            'csp_report_only' => ['nullable', 'boolean'],
        ]);
        $actor = $this->actor();
        $this->settings->set('headers.hsts.enabled', $request->boolean('hsts_enabled'), $actor);
        $this->settings->set('headers.hsts.max_age', $v['hsts_max_age'], $actor);
        $this->settings->set('headers.x_frame_options.value', $v['x_frame_options'], $actor);
        $this->settings->set('headers.referrer_policy.value', $v['referrer_policy'], $actor);
        $this->settings->set('headers.csp.enabled', $request->boolean('csp_enabled'), $actor);
        $this->settings->set('headers.csp.report_only', $request->boolean('csp_report_only'), $actor);
        $this->audit->log('settings.headers', 'config', 'headers');

        return back()->with('status', 'Security-Header gespeichert.');
    }

    /**
     * @return array<int, string>
     */
    private function lines(string $value, string $extra = ''): array
    {
        $pattern = $extra !== '' ? '/[\r\n'.preg_quote($extra, '/').']+/' : '/[\r\n]+/';

        return array_values(array_filter(array_map('trim', preg_split($pattern, $value) ?: []), static fn ($v) => $v !== ''));
    }

    /**
     * @return array<int, string>
     */
    private function countries(string $value): array
    {
        return array_values(array_filter(array_map(
            static fn ($c) => strtoupper(trim((string) $c)),
            preg_split('/[\s,]+/', $value) ?: [],
        ), static fn ($c) => preg_match('/^[A-Z]{2}$/', $c) === 1));
    }

    private function actor(): string
    {
        return (string) (auth()->id() ?? 'ui');
    }

    private function authorizeManage(): void
    {
        abort_unless(Gate::allows('manageWAF'), 403);
    }
}
