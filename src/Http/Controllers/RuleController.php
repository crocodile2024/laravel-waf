<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Http\Controllers;

use Crocodile2024\WAF\Http\Requests\RuleRequest;
use Crocodile2024\WAF\Http\Requests\RuleTestRequest;
use Crocodile2024\WAF\Models\Rule;
use Crocodile2024\WAF\Services\AuditLogger;
use Crocodile2024\WAF\Services\RuleRegistry;
use Crocodile2024\WAF\Services\RuleTester;
use Illuminate\Contracts\View\View;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\Gate;

class RuleController extends Controller
{
    public function __construct(
        private readonly RuleRegistry $registry,
        private readonly AuditLogger $audit,
    ) {}

    public function index(): View
    {
        return view('waf::pages.rules', [
            'title' => 'Regeln',
            'coreRules' => Rule::query()->where('source', 'core')->orderBy('code')->get()->groupBy(fn (Rule $r) => explode('-', $r->code)[1] ?? 'ALLGEMEIN'),
            'customRules' => Rule::query()->where('source', '!=', 'core')->orderBy('priority')->get(),
            'canManage' => Gate::allows('manageWAF'),
        ]);
    }

    public function create(): View
    {
        $this->authorizeManage();

        return view('waf::pages.rule-edit', ['title' => 'Regel anlegen', 'rule' => new Rule]);
    }

    public function store(RuleRequest $request): RedirectResponse
    {
        $this->authorizeManage();
        $rule = Rule::query()->create($request->toRule('custom'));
        $this->audit->log('rule.create', 'rule', $rule->code, ['after' => $rule->toDefinition()]);
        $this->registry->recompile();

        return redirect()->route('waf.ui.rules.index')->with('status', 'Regel „'.$rule->name.'“ angelegt.');
    }

    public function edit(Rule $rule): View
    {
        $this->authorizeManage();

        return view('waf::pages.rule-edit', ['title' => 'Regel bearbeiten', 'rule' => $rule]);
    }

    public function update(RuleRequest $request, Rule $rule): RedirectResponse
    {
        $this->authorizeManage();
        if ($rule->isCore()) {
            return back()->withErrors(['rule' => 'Mitgelieferte Regeln sind nicht editierbar (nur deaktivierbar / mit Ausnahmen versehbar).']);
        }
        $before = $rule->toDefinition();
        $rule->update($request->toRule($rule->source));
        $this->audit->log('rule.update', 'rule', $rule->code, ['before' => $before, 'after' => $rule->toDefinition()]);
        $this->registry->recompile();

        return redirect()->route('waf.ui.rules.index')->with('status', 'Regel aktualisiert.');
    }

    public function destroy(Rule $rule): RedirectResponse
    {
        $this->authorizeManage();
        if ($rule->isCore()) {
            return back()->withErrors(['rule' => 'Mitgelieferte Regeln können nicht gelöscht werden.']);
        }
        $this->audit->log('rule.delete', 'rule', $rule->code, ['before' => $rule->toDefinition()]);
        $rule->delete();
        $this->registry->recompile();

        return redirect()->route('waf.ui.rules.index')->with('status', 'Regel gelöscht.');
    }

    public function toggle(Rule $rule): RedirectResponse
    {
        $this->authorizeManage();
        $rule->update(['is_active' => ! $rule->is_active]);
        $this->audit->log('rule.toggle', 'rule', $rule->code, ['is_active' => $rule->is_active]);
        $this->registry->recompile();

        return back()->with('status', 'Regel '.($rule->is_active ? 'aktiviert' : 'deaktiviert').'.');
    }

    public function test(RuleTestRequest $request, RuleTester $tester): JsonResponse
    {
        $headers = [];
        foreach (preg_split('/\r?\n/', (string) $request->input('headers', '')) ?: [] as $line) {
            if (str_contains($line, ':')) {
                [$k, $v] = explode(':', $line, 2);
                $headers[strtolower(trim($k))] = trim($v);
            }
        }
        $headers['content-type'] ??= 'application/x-www-form-urlencoded';

        return response()->json($tester->test(
            strtoupper((string) $request->input('method', 'GET')),
            (string) $request->input('path', '/'),
            (string) $request->input('body', ''),
            $headers,
        ));
    }

    private function authorizeManage(): void
    {
        abort_unless(Gate::allows('manageWAF'), 403, 'Keine Berechtigung zum Ändern der WAF.');
    }
}
