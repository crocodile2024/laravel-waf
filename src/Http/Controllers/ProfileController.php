<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Http\Controllers;

use Crocodile2024\WAF\Engine\Mode;
use Crocodile2024\WAF\Models\InspectionProfile;
use Crocodile2024\WAF\Models\ProfileAssignment;
use Crocodile2024\WAF\Services\AuditLogger;
use Illuminate\Contracts\View\View;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;

class ProfileController extends Controller
{
    public function __construct(private readonly AuditLogger $audit) {}

    public function index(): View
    {
        return view('waf::pages.profiles', [
            'title' => 'Profile',
            'profiles' => InspectionProfile::query()->orderBy('name')->get(),
            'assignments' => ProfileAssignment::query()->where('profile_type', 'inspection')->orderBy('priority')->get(),
            'modes' => Mode::cases(),
            'canManage' => Gate::allows('manageWAF'),
        ]);
    }

    public function store(Request $request): RedirectResponse
    {
        $this->authorizeManage();
        $v = $request->validate([
            'name' => ['required', 'string', 'max:64'],
            'paranoia_level' => ['nullable', 'integer', 'between:1,4'],
            'inbound_threshold' => ['nullable', 'integer', 'min:1'],
            'mode_override' => ['nullable', 'in:'.implode(',', Mode::values())],
            'allowed_countries' => ['nullable', 'string', 'max:1024'],
        ]);
        $countries = array_values(array_filter(array_map(
            static fn ($c) => strtoupper(trim((string) $c)),
            preg_split('/[\s,]+/', (string) ($v['allowed_countries'] ?? '')) ?: [],
        ), static fn ($c) => preg_match('/^[A-Z]{2}$/', $c) === 1));

        $profile = InspectionProfile::query()->updateOrCreate(['name' => $v['name']], [
            'paranoia_level' => $v['paranoia_level'] ?? null,
            'inbound_threshold' => $v['inbound_threshold'] ?? null,
            'mode_override' => $v['mode_override'] ?? null,
            'allowed_countries' => $countries ?: null,
        ]);
        $this->audit->log('profile.save', 'inspection_profile', $profile->id, ['name' => $profile->name]);

        return back()->with('status', 'Profil „'.$profile->name.'" gespeichert.');
    }

    public function destroy(InspectionProfile $profile): RedirectResponse
    {
        $this->authorizeManage();
        ProfileAssignment::query()->where('profile_type', 'inspection')->where('profile_id', $profile->id)->delete();
        $this->audit->log('profile.delete', 'inspection_profile', $profile->id);
        $profile->delete();

        return back()->with('status', 'Profil gelöscht.');
    }

    public function assign(Request $request): RedirectResponse
    {
        $this->authorizeManage();
        $v = $request->validate([
            'profile_id' => ['required', 'string', 'exists:waf_inspection_profiles,id'],
            'match_type' => ['required', 'in:route_name,path_pattern,method'],
            'match_value' => ['required', 'string', 'max:255'],
            'priority' => ['nullable', 'integer', 'between:0,1000'],
        ]);
        ProfileAssignment::query()->create([
            'profile_type' => 'inspection',
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
