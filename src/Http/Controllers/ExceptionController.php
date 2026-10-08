<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Http\Controllers;

use Crocodile2024\WAF\Models\LearningHit;
use Crocodile2024\WAF\Models\WafException;
use Crocodile2024\WAF\Services\AuditLogger;
use Crocodile2024\WAF\Services\ExceptionService;
use Crocodile2024\WAF\Support\IpMatcher;
use Illuminate\Contracts\View\View;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;

class ExceptionController extends Controller
{
    public function __construct(
        private readonly ExceptionService $exceptions,
        private readonly AuditLogger $audit,
    ) {}

    public function index(Request $request): View
    {
        return view('waf::pages.exceptions', [
            'title' => 'Ausnahmen',
            'exceptions' => WafException::query()->orderByDesc('created_at')->paginate(50),
            'suggestions' => LearningHit::query()->where('status', 'open')->orderByDesc('hit_count')->limit(100)->get(),
            'canManage' => Gate::allows('manageWAF'),
            'prefill' => $request->only(['rule_code', 'scope_type', 'scope_value', 'parameter']),
        ]);
    }

    public function store(Request $request): RedirectResponse
    {
        $this->authorizeManage();
        $validated = $request->validate([
            'rule_code' => ['nullable', 'string', 'max:64'],
            'rule_tag' => ['nullable', 'string', 'max:64'],
            'scope_type' => ['required', 'in:global,route_name,path_pattern'],
            'scope_value' => ['nullable', 'string', 'max:255'],
            'parameter' => ['nullable', 'string', 'max:255'],
            'ip_cidr' => ['nullable', 'string', 'max:49'],
            'comment' => ['nullable', 'string', 'max:255'],
            'expires_at' => ['nullable', 'date'],
        ]);
        if (($validated['rule_code'] ?? null) === null && ($validated['rule_tag'] ?? null) === null) {
            return back()->withErrors(['rule_code' => 'Regel-ID oder Tag ist erforderlich.'])->withInput();
        }
        if (! empty($validated['ip_cidr']) && ! IpMatcher::isValidCidr($validated['ip_cidr'])) {
            return back()->withErrors(['ip_cidr' => 'Ungültige IP/CIDR.'])->withInput();
        }
        $exception = WafException::query()->create($validated + ['created_by' => (string) (auth()->id() ?? 'ui')]);
        $this->exceptions->flush();
        $this->audit->log('exception.create', 'exception', $exception->id, $validated);

        return redirect()->route('waf.ui.exceptions.index')->with('status', 'Ausnahme angelegt.');
    }

    public function destroy(WafException $exception): RedirectResponse
    {
        $this->authorizeManage();
        $this->audit->log('exception.delete', 'exception', $exception->id);
        $exception->delete();
        $this->exceptions->flush();

        return back()->with('status', 'Ausnahme gelöscht.');
    }

    public function acceptSuggestion(Request $request, LearningHit $hit): RedirectResponse
    {
        $this->authorizeManage();
        WafException::query()->create([
            'rule_code' => $hit->rule_code,
            'scope_type' => $hit->route_name !== '' ? 'route_name' : 'path_pattern',
            'scope_value' => $hit->route_name !== '' ? $hit->route_name : $hit->path_pattern,
            'parameter' => $hit->parameter ?: null,
            'comment' => 'Aus Lernmodus-Vorschlag übernommen',
            'created_by' => (string) (auth()->id() ?? 'ui'),
        ]);
        $hit->update(['status' => 'accepted']);
        $this->exceptions->flush();
        $this->audit->log('exception.accept_suggestion', 'learning_hit', $hit->id);

        return back()->with('status', 'Vorschlag als Ausnahme übernommen.');
    }

    public function dismissSuggestion(LearningHit $hit): RedirectResponse
    {
        $this->authorizeManage();
        $hit->update(['status' => 'dismissed']);

        return back()->with('status', 'Vorschlag verworfen.');
    }

    private function authorizeManage(): void
    {
        abort_unless(Gate::allows('manageWAF'), 403);
    }
}
