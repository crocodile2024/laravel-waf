@extends('waf::layouts.app')
@section('content')
    @if($canManage)
    <div class="card">
        <h3 style="margin-top:0;">Ausnahme anlegen</h3>
        <form method="POST" action="{{ route('waf.ui.exceptions.store') }}" style="display:grid;gap:10px;grid-template-columns:1fr 1fr 1fr;">
            @csrf
            <div><label>Regel-ID</label><input name="rule_code" value="{{ $prefill['rule_code'] ?? '' }}" placeholder="WAF-SQLI-002"></div>
            <div><label>oder Regel-Tag</label><input name="rule_tag" placeholder="sqli"></div>
            <div><label>Geltungsbereich</label>
                <select name="scope_type">
                    <option value="global">global</option>
                    <option value="route_name" @selected(($prefill['scope_type']??'')==='route_name')>Route-Name</option>
                    <option value="path_pattern" @selected(($prefill['scope_type']??'')==='path_pattern')>Pfad-Muster</option>
                </select></div>
            <div><label>Bereichswert</label><input name="scope_value" value="{{ $prefill['scope_value'] ?? '' }}" placeholder="/api/* oder route.name"></div>
            <div><label>Parameter (optional)</label><input name="parameter" value="{{ $prefill['parameter'] ?? '' }}"></div>
            <div><label>IP/CIDR (optional)</label><input name="ip_cidr"></div>
            <div><label>Kommentar</label><input name="comment"></div>
            <div><label>Läuft ab (optional)</label><input type="datetime-local" name="expires_at"></div>
            <div style="align-self:end;"><button class="btn" type="submit">Anlegen</button></div>
        </form>
    </div>
    @endif

    <div class="card">
        <h3 style="margin-top:0;">Aktive Ausnahmen</h3>
        @if($exceptions->isEmpty())
            <div class="empty">Keine Ausnahmen definiert.</div>
        @else
        <table>
            <thead><tr><th>Regel/Tag</th><th>Bereich</th><th>Parameter</th><th>IP</th><th>Läuft ab</th><th></th></tr></thead>
            <tbody>
                @foreach($exceptions as $ex)
                    <tr>
                        <td><code>{{ $ex->rule_code ?? $ex->rule_tag }}</code></td>
                        <td>{{ $ex->scope_type }}{{ $ex->scope_value ? ': '.$ex->scope_value : '' }}</td>
                        <td>{{ $ex->parameter ?? '–' }}</td><td>{{ $ex->ip_cidr ?? '–' }}</td>
                        <td>{{ $ex->expires_at?->format('d.m.Y') ?? '–' }}</td>
                        <td>@if($canManage)<form method="POST" action="{{ route('waf.ui.exceptions.destroy', $ex) }}" style="display:inline;">@csrf @method('DELETE')<button class="btn btn-ghost" type="submit">Löschen</button></form>@endif</td>
                    </tr>
                @endforeach
            </tbody>
        </table>
        {{ $exceptions->links() }}
        @endif
    </div>

    <div class="card">
        <h3 style="margin-top:0;">Vorschläge (Lernmodus)</h3>
        @if($suggestions->isEmpty())
            <div class="empty">Keine offenen Vorschläge. Im Lernmodus gesammelte Treffer erscheinen hier gruppiert.</div>
        @else
        <table>
            <thead><tr><th>Regel</th><th>Route/Pfad</th><th>Parameter</th><th>Treffer</th><th>IPs</th><th></th></tr></thead>
            <tbody>
                @foreach($suggestions as $hit)
                    <tr @class(['']) style="{{ $hit->isSuspicious() ? 'opacity:.7;' : '' }}">
                        <td><code>{{ $hit->rule_code }}</code></td>
                        <td>{{ $hit->route_name ?: $hit->path_pattern }}</td>
                        <td>{{ $hit->parameter ?: '–' }}</td>
                        <td>{{ $hit->hit_count }}</td>
                        <td>{{ $hit->distinct_ip_count }} @if($hit->isSuspicious())<span title="Nur eine IP – verdächtig">⚠</span>@endif</td>
                        <td>
                            @if($canManage)
                            <form method="POST" action="{{ route('waf.ui.exceptions.accept', $hit) }}" style="display:inline;">@csrf<button class="btn btn-ghost" type="submit">Übernehmen</button></form>
                            <form method="POST" action="{{ route('waf.ui.exceptions.dismiss', $hit) }}" style="display:inline;">@csrf<button class="btn btn-ghost" type="submit">Verwerfen</button></form>
                            @endif
                        </td>
                    </tr>
                @endforeach
            </tbody>
        </table>
        @endif
    </div>
@endsection
