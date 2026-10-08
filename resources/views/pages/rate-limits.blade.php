@extends('waf::layouts.app')
@section('content')
    @if($canManage)
    <div class="card">
        <h3 style="margin-top:0;">Profil anlegen / aktualisieren</h3>
        <form method="POST" action="{{ route('waf.ui.rate-limits.store') }}" style="display:grid;gap:10px;grid-template-columns:repeat(4,1fr);">
            @csrf
            <div><label>Name</label><input name="name" required></div>
            <div><label>Schlüssel</label><select name="key_type"><option>ip</option><option>ip+route</option><option>user</option><option>ip+user_agent</option><option value="header">header</option></select></div>
            <div><label>Header (bei „header")</label><input name="key_header"></div>
            <div><label>Limit</label><input type="number" name="limit" min="1" value="60" required></div>
            <div><label>Fenster (Sek.)</label><input type="number" name="window_seconds" min="1" value="60" required></div>
            <div><label>Burst</label><input type="number" name="burst" min="0" value="0"></div>
            <div><label>Aktion</label><select name="action_type"><option value="429">429</option><option value="challenge">Challenge</option><option value="ban">Ban</option><option value="score">Score</option></select></div>
            <div><label>Score-Punkte</label><input type="number" name="action_points" min="1" value="5"></div>
            <div style="align-self:end;"><button class="btn" type="submit">Speichern</button></div>
        </form>
    </div>
    @endif
    <div class="card">
        <h3 style="margin-top:0;">Profile</h3>
        @if($profiles->isEmpty())<div class="empty">Keine Profile. Vordefinierte Schutzmechanismen (Login-Bruteforce, 404-Flut) sind in der Config aktiv.</div>@else
        <table><thead><tr><th>Name</th><th>Schlüssel</th><th>Limit/Fenster</th><th>Burst</th><th>Aktion</th><th></th></tr></thead><tbody>
            @foreach($profiles as $p)<tr>
                <td><code>{{ $p->name }}</code></td><td>{{ $p->key_type }}{{ $p->key_header ? ':'.$p->key_header : '' }}</td>
                <td>{{ $p->limit }} / {{ $p->window_seconds }}s</td><td>{{ $p->burst }}</td><td>{{ $p->action['type'] ?? '429' }}</td>
                <td>@if($canManage)<form method="POST" action="{{ route('waf.ui.rate-limits.destroy',$p) }}" style="display:inline;">@csrf @method('DELETE')<button class="btn btn-ghost">Löschen</button></form>@endif</td>
            </tr>@endforeach
        </tbody></table>@endif
    </div>
    <div class="card">
        <h3 style="margin-top:0;">Zuweisungen</h3>
        @if($canManage && $profiles->isNotEmpty())
        <form method="POST" action="{{ route('waf.ui.rate-limits.assign') }}" style="display:flex;gap:8px;align-items:end;flex-wrap:wrap;margin-bottom:12px;">
            @csrf
            <div><label>Profil</label><select name="profile_id">@foreach($profiles as $p)<option value="{{ $p->id }}">{{ $p->name }}</option>@endforeach</select></div>
            <div><label>Typ</label><select name="match_type"><option value="route_name">Route-Name</option><option value="path_pattern">Pfad-Muster</option><option value="method">Methode</option></select></div>
            <div><label>Wert</label><input name="match_value" placeholder="/login oder login"></div>
            <div><label>Priorität</label><input type="number" name="priority" value="500"></div>
            <button class="btn" type="submit">Zuweisen</button>
        </form>@endif
        @if($assignments->isEmpty())<div class="empty">Keine Zuweisungen.</div>@else
        <table><thead><tr><th>Typ</th><th>Wert</th><th>Priorität</th><th></th></tr></thead><tbody>
            @foreach($assignments as $a)<tr><td>{{ $a->match_type }}</td><td><code>{{ $a->match_value }}</code></td><td>{{ $a->priority }}</td>
                <td>@if($canManage)<form method="POST" action="{{ route('waf.ui.rate-limits.unassign',$a) }}" style="display:inline;">@csrf @method('DELETE')<button class="btn btn-ghost">Entfernen</button></form>@endif</td></tr>@endforeach
        </tbody></table>@endif
    </div>
@endsection
