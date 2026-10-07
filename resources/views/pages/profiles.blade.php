@extends('waf::layouts.app')
@section('content')
    @if($canManage)
    <div class="card">
        <h3 style="margin-top:0;">Inspektionsprofil anlegen / aktualisieren</h3>
        <form method="POST" action="{{ route('waf.ui.profiles.store') }}" style="display:grid;gap:10px;grid-template-columns:repeat(4,1fr);">
            @csrf
            <div><label>Name</label><input name="name" required></div>
            <div><label>Paranoia (leer = global)</label><input type="number" name="paranoia_level" min="1" max="4"></div>
            <div><label>Schwellwert (leer = global)</label><input type="number" name="inbound_threshold" min="1"></div>
            <div><label>Modus-Override</label><select name="mode_override"><option value="">(global)</option>@foreach($modes as $m)<option value="{{ $m->value }}">{{ $m->label() }}</option>@endforeach</select></div>
            <div style="grid-column:1/4;"><label>Erlaubte Länder (z. B. Admin-Bereich: DE AT CH)</label><input name="allowed_countries" style="width:100%;"></div>
            <div style="align-self:end;"><button class="btn" type="submit">Speichern</button></div>
        </form>
    </div>
    @endif
    <div class="card">
        <h3 style="margin-top:0;">Profile</h3>
        @if($profiles->isEmpty())<div class="empty">Keine Inspektionsprofile.</div>@else
        <table><thead><tr><th>Name</th><th>Paranoia</th><th>Schwellwert</th><th>Modus</th><th>Länder</th><th></th></tr></thead><tbody>
            @foreach($profiles as $p)<tr><td>{{ $p->name }}</td><td>{{ $p->paranoia_level ?? '–' }}</td><td>{{ $p->inbound_threshold ?? '–' }}</td>
                <td>{{ $p->mode_override ?? '–' }}</td><td>{{ implode(' ', (array) $p->allowed_countries) }}</td>
                <td>@if($canManage)<form method="POST" action="{{ route('waf.ui.profiles.destroy',$p) }}" style="display:inline;">@csrf @method('DELETE')<button class="btn btn-ghost">Löschen</button></form>@endif</td></tr>@endforeach
        </tbody></table>@endif
    </div>
    <div class="card">
        <h3 style="margin-top:0;">Zuweisungen</h3>
        @if($canManage && $profiles->isNotEmpty())
        <form method="POST" action="{{ route('waf.ui.profiles.assign') }}" style="display:flex;gap:8px;align-items:end;flex-wrap:wrap;margin-bottom:12px;">
            @csrf
            <div><label>Profil</label><select name="profile_id">@foreach($profiles as $p)<option value="{{ $p->id }}">{{ $p->name }}</option>@endforeach</select></div>
            <div><label>Typ</label><select name="match_type"><option value="route_name">Route-Name</option><option value="path_pattern">Pfad-Muster</option><option value="method">Methode</option></select></div>
            <div><label>Wert</label><input name="match_value" placeholder="admin/*"></div>
            <div><label>Priorität</label><input type="number" name="priority" value="500"></div>
            <button class="btn" type="submit">Zuweisen</button>
        </form>@endif
        @if($assignments->isEmpty())<div class="empty">Keine Zuweisungen.</div>@else
        <table><thead><tr><th>Typ</th><th>Wert</th><th>Priorität</th><th></th></tr></thead><tbody>
            @foreach($assignments as $a)<tr><td>{{ $a->match_type }}</td><td><code>{{ $a->match_value }}</code></td><td>{{ $a->priority }}</td>
                <td>@if($canManage)<form method="POST" action="{{ route('waf.ui.profiles.unassign',$a) }}" style="display:inline;">@csrf @method('DELETE')<button class="btn btn-ghost">Entfernen</button></form>@endif</td></tr>@endforeach
        </tbody></table>@endif
    </div>
@endsection
