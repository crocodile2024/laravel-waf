<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Http\Controllers;

use Crocodile2024\WAF\Engine\Scoring\Severity;
use Crocodile2024\WAF\Models\NotificationChannel;
use Crocodile2024\WAF\Services\AuditLogger;
use Crocodile2024\WAF\Services\NotificationService;
use Illuminate\Contracts\View\View;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;

class NotificationController extends Controller
{
    public const EVENTS = ['ban', 'attack_wave', 'critical_hit', 'mode_change', 'config_change', 'redis_down', 'geoip_stale'];

    public function __construct(
        private readonly AuditLogger $audit,
        private readonly NotificationService $notifications,
    ) {}

    public function index(): View
    {
        return view('waf::pages.notifications', [
            'title' => 'Benachrichtigungen',
            'channels' => NotificationChannel::query()->orderBy('type')->get(),
            'eventTypes' => self::EVENTS,
            'severities' => Severity::values(),
            'canManage' => Gate::allows('manageWAF'),
        ]);
    }

    public function store(Request $request): RedirectResponse
    {
        $this->authorizeManage();
        $v = $request->validate([
            'type' => ['required', 'in:mail,webhook'],
            'target' => ['required', 'string', 'max:512'],
            'secret' => ['nullable', 'string', 'max:255'],
            'events' => ['required', 'array', 'min:1'],
            'events.*' => ['in:'.implode(',', self::EVENTS)],
            'min_severity' => ['required', 'in:'.implode(',', Severity::values())],
            'digest' => ['required', 'in:instant,hourly,daily'],
        ]);
        if ($v['type'] === 'mail' && ! filter_var($v['target'], FILTER_VALIDATE_EMAIL)) {
            return back()->withErrors(['target' => 'Ungültige E-Mail-Adresse.'])->withInput();
        }
        if ($v['type'] === 'webhook' && ! filter_var($v['target'], FILTER_VALIDATE_URL)) {
            return back()->withErrors(['target' => 'Ungültige URL.'])->withInput();
        }
        $channel = NotificationChannel::query()->create([
            'type' => $v['type'],
            'target' => $v['target'],
            'secret' => $v['secret'] ?? null,
            'events' => array_values($v['events']),
            'min_severity' => $v['min_severity'],
            'digest' => $v['digest'],
            'is_active' => true,
        ]);
        $this->audit->log('notification.create', 'notification_channel', $channel->id, ['type' => $v['type']]);

        return back()->with('status', 'Kanal angelegt.');
    }

    public function destroy(NotificationChannel $channel): RedirectResponse
    {
        $this->authorizeManage();
        $this->audit->log('notification.delete', 'notification_channel', $channel->id);
        $channel->delete();

        return back()->with('status', 'Kanal gelöscht.');
    }

    public function test(NotificationChannel $channel): RedirectResponse
    {
        $this->authorizeManage();
        $this->notifications->notify('config_change', 'notice', ['test' => true, 'message' => 'Testversand aus der WAF-Oberfläche.']);

        return back()->with('status', 'Testbenachrichtigung ausgelöst.');
    }

    private function authorizeManage(): void
    {
        abort_unless(Gate::allows('manageWAF'), 403);
    }
}
