<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Http\Controllers;

use Crocodile2024\WAF\Models\ProfileAssignment;
use Crocodile2024\WAF\Models\RateLimitProfile;
use Crocodile2024\WAF\Services\AuditLogger;
use Illuminate\Contracts\View\View;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;

class RateLimitController extends Controller
{
    public function __construct(private readonly AuditLogger $audit) {}

    public function index(): View
    {
        return view('waf::pages.rate-limits', [
            'title' => 'Rate-Limits',
            'profiles' => RateLimitProfile::query()->orderBy('name')->get(),
            'assignments' => ProfileAssignment::query()->where('profile_type', 'rate_limit')->orderBy('priority')->get(),
            'canManage' => Gate::allows('manageWAF'),
        ]);
    }

    public function store(Request $request): RedirectResponse
    {
        $this->authorizeManage();
        $v = $request->validate([
            'name' => ['required', 'string', 'max:64', 'regex:/^[a-z0-9_\-]+$/i'],
            'key_type' => ['required', 'in:ip,ip+route,user,ip+user_agent,header'],
            'key_header' => ['nullable', 'string', 'max:128'],
            'limit' => ['required', 'integer', 'min:1'],
            'window_seconds' => ['required', 'integer', 'min:1'],
            'burst' => ['nullable', 'integer', 'min:0'],
            'action_type' => ['required', 'in:429,challenge,ban,score'],
            'action_points' => ['nullable', 'integer', 'min:1'],
        ]);
        $action = ['type' => $v['action_type']];
        if ($v['action_type'] === 'score') {
            $action['points'] = $v['action_points'] ?? 5;
        }
        $profile = RateLimitProfile::query()->updateOrCreate(['name' => $v['name']], [
            'key_type' => $v['key_type'],
            'key_header' => $v['key_header'] ?? null,
            'limit' => $v['limit'],
            'window_seconds' => $v['window_seconds'],
            'burst' => $v['burst'] ?? 0,
            'action' => $action,
            'is_active' => true,
        ]);
        $this->audit->log('ratelimit.save', 'rate_limit_profile', $profile->id, ['name' => $profile->name]);

        return back()->with('status', 'Profil „'.$profile->name.'" gespeichert.');
    }

    public function destroy(RateLimitProfile $profile): RedirectResponse
    {
        $this->authorizeManage();
        ProfileAssignment::query()->where('profile_type', 'rate_limit')->where('profile_id', $profile->id)->delete();
        $this->audit->log('ratelimit.delete', 'rate_limit_profile', $profile->id);
        $profile->delete();

        return back()->with('status', 'Profil gelöscht.');
    }

    public function assign(Request $request): RedirectResponse
    {
        $this->authorizeManage();
        $v = $request->validate([
            'profile_id' => ['required', 'string', 'exists:waf_rate_limit_profiles,id'],
            'match_type' => ['required', 'in:route_name,path_pattern,method'],
            'match_value' => ['required', 'string', 'max:255'],
            'priority' => ['nullable', 'integer', 'between:0,1000'],
        ]);
        ProfileAssignment::query()->create([
            'profile_type' => 'rate_limit',
            'profile_id' => $v['profile_id'],
            'match_type' => $v['match_type'],
            'match_value' => $v['match_value'],
            'priority' => $v['priority'] ?? 500,
        ]);

        return back()->with('status', 'Zuweisung angelegt.');
    }

    public function unassign(ProfileAssignment $assignment): RedirectResponse
    {
        $this->authorizeManage();
        $assignment->delete();

        return back()->with('status', 'Zuweisung entfernt.');
    }

    private function authorizeManage(): void
    {
        abort_unless(Gate::allows('manageWAF'), 403);
    }
}
