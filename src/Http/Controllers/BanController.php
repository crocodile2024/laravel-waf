<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Http\Controllers;

use Crocodile2024\WAF\Models\Ban;
use Crocodile2024\WAF\Services\AuditLogger;
use Crocodile2024\WAF\Services\BanService;
use Crocodile2024\WAF\Support\IpMatcher;
use Illuminate\Contracts\View\View;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;

class BanController extends Controller
{
    public function __construct(
        private readonly BanService $bans,
        private readonly AuditLogger $audit,
    ) {}

    public function index(Request $request): View
    {
        $history = $request->boolean('history');
        $query = Ban::query()->orderByDesc('created_at');
        $query = $history ? $query->whereNotNull('lifted_at') : $query->active();

        return view('waf::pages.bans', [
            'title' => 'Sperren',
            'bans' => $query->paginate(50)->withQueryString(),
            'history' => $history,
            'canManage' => Gate::allows('manageWAF'),
        ]);
    }

    public function store(Request $request): RedirectResponse
    {
        $this->authorizeManage();
        $validated = $request->validate([
            'ip' => ['required', 'string', 'max:45'],
            'minutes' => ['nullable', 'integer', 'min:1'],
            'reason' => ['nullable', 'string', 'max:255'],
        ]);
        if (! IpMatcher::isValidIp($validated['ip'])) {
            return back()->withErrors(['ip' => 'Ungültige IP-Adresse.'])->withInput();
        }
        $ban = $this->bans->ban($validated['ip'], $validated['minutes'] ?? null, $validated['reason'] ?? 'manuell (UI)', 'manual');
        $this->audit->log('ban.create', 'ban', $ban->id, ['ip' => $validated['ip']]);

        return back()->with('status', 'IP gesperrt: '.$validated['ip']);
    }

    public function destroy(Request $request): RedirectResponse
    {
        $this->authorizeManage();
        $ips = (array) $request->input('ip_key', []);
        if ($request->filled('single')) {
            $ips = [(string) $request->input('single')];
        }
        $count = 0;
        foreach ($ips as $ipKey) {
            $this->bans->unban((string) $ipKey, (string) (auth()->id() ?? 'ui'));
            $count++;
        }
        $this->audit->log('ban.lift', 'ban', null, ['count' => $count]);

        return back()->with('status', "{$count} Sperre(n) aufgehoben.");
    }

    private function authorizeManage(): void
    {
        abort_unless(Gate::allows('manageWAF'), 403);
    }
}
