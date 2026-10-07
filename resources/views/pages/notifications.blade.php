@extends('waf::layouts.app')
@section('content')
    @if($canManage)
    <div class="card">
        <h3 style="margin-top:0;">Kanal anlegen</h3>
        <form method="POST" action="{{ route('waf.ui.notifications.store') }}">
            @csrf
            <div style="display:grid;gap:10px;grid-template-columns:repeat(4,1fr);">
                <div><label>Typ</label><select name="type"><option value="mail">E-Mail</option><option value="webhook">Webhook</option></select></div>
                <div style="grid-column:2/4;"><label>Ziel (E-Mail oder URL)</label><input name="target" required style="width:100%;"></div>
                <div><label>Secret (Webhook-HMAC)</label><input name="secret"></div>
                <div><label>Mindestschwere</label><select name="min_severity">@foreach($severities as $s)<option value="{{ $s }}">{{ $s }}</option>@endforeach</select></div>
                <div><label>Zustellung</label><select name="digest"><option value="instant">sofort</option><option value="hourly">stündlich</option><option value="daily">täglich</option></select></div>
            </div>
            <div style="margin-top:12px;"><label>Ereignisarten</label><div style="display:flex;gap:16px;flex-wrap:wrap;">
                @foreach($eventTypes as $et)<label style="display:inline;"><input type="checkbox" name="events[]" value="{{ $et }}"> {{ $et }}</label>@endforeach
            </div></div>
            <div style="margin-top:12px;"><button class="btn" type="submit">Anlegen</button></div>
        </form>
    </div>
    @endif
    <div class="card">
        @if($channels->isEmpty())<div class="empty">Keine Kanäle. Webhooks werden mit HMAC-SHA256 im Header <code>X-WAF-Signature</code> signiert.</div>@else
        <table><thead><tr><th>Typ</th><th>Ziel</th><th>Ereignisse</th><th>Schwere</th><th>Zustellung</th><th></th></tr></thead><tbody>
            @foreach($channels as $c)<tr><td>{{ $c->type }}</td><td title="{{ $c->target }}">{{ Str::limit($c->target, 40) }}</td>
                <td>{{ implode(', ', (array) $c->events) }}</td><td>{{ $c->min_severity }}</td><td>{{ $c->digest }}</td>
                <td>@if($canManage)
                    <form method="POST" action="{{ route('waf.ui.notifications.test',$c) }}" style="display:inline;">@csrf<button class="btn btn-ghost">Test</button></form>
                    <form method="POST" action="{{ route('waf.ui.notifications.destroy',$c) }}" style="display:inline;">@csrf @method('DELETE')<button class="btn btn-ghost">Löschen</button></form>
                @endif</td></tr>@endforeach
        </tbody></table>@endif
    </div>
@endsection
