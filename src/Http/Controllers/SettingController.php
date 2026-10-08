<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Http\Controllers;

use Crocodile2024\WAF\Engine\Mode;
use Crocodile2024\WAF\Services\AuditLogger;
use Crocodile2024\WAF\Services\ConfigManager;
use Crocodile2024\WAF\Services\SettingsRepository;
use Illuminate\Contracts\View\View;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;

class SettingController extends Controller
{
    public function __construct(
        private readonly ConfigManager $config,
        private readonly SettingsRepository $settings,
        private readonly AuditLogger $audit,
    ) {}

    public function index(): View
    {
        return view('waf::pages.settings', [
            'title' => 'Einstellungen',
            'config' => $this->config->all(),
            'modes' => Mode::cases(),
            'canManage' => Gate::allows('manageWAF'),
        ]);
    }

    public function update(Request $request): RedirectResponse
    {
        $this->authorizeManage();
        $validated = $request->validate([
            'mode' => ['required', 'in:'.implode(',', Mode::values())],
            'paranoia_level' => ['required', 'integer', 'between:1,4'],
            'inbound_threshold' => ['required', 'integer', 'min:1'],
            'reputation_half_life_minutes' => ['required', 'integer', 'min:1'],
            'reputation_ban_threshold' => ['required', 'integer', 'min:1'],
            'anonymize_after_days' => ['required', 'integer', 'min:0'],
            'retention_days' => ['required', 'integer', 'min:1'],
            'block_page_contact' => ['nullable', 'string', 'max:255'],
            'confirm' => ['nullable', 'string'],
        ]);

        // Kritische Aktion: Modus auf "off" erfordert Bestätigung
        if ($validated['mode'] === 'off' && $request->input('confirm') !== 'BESTÄTIGEN') {
            return back()->withErrors(['mode' => 'Modus „Aus" erfordert die Eingabe des Wortes BESTÄTIGEN.'])->withInput();
        }

        $actor = (string) (auth()->id() ?? 'ui');
        $old = $this->config->mode()->value;
        $this->settings->set('mode', $validated['mode'], $actor);
        $this->settings->set('paranoia_level', $validated['paranoia_level'], $actor);
        $this->settings->set('inbound_threshold', $validated['inbound_threshold'], $actor);
        $this->settings->set('reputation.half_life_minutes', $validated['reputation_half_life_minutes'], $actor);
        $this->settings->set('reputation.ban_threshold', $validated['reputation_ban_threshold'], $actor);
        $this->settings->set('privacy.anonymize_after_days', $validated['anonymize_after_days'], $actor);
        $this->settings->set('privacy.retention_days', $validated['retention_days'], $actor);
        $this->settings->set('block_page.contact', $validated['block_page_contact'] ?? '', $actor);

        $this->audit->log('settings.update', 'config', 'global', ['mode_from' => $old, 'mode_to' => $validated['mode']]);

        return back()->with('status', 'Einstellungen gespeichert.');
    }

    private function authorizeManage(): void
    {
        abort_unless(Gate::allows('manageWAF'), 403);
    }
}
