@extends('waf::layouts.app')
@section('content')
    <div style="display:flex;gap:8px;margin-bottom:16px;">
        <a class="btn {{ $tab==='reports'?'btn-ghost':'' }}" href="{{ route('waf.ui.headers.index') }}">Header</a>
        <a class="btn {{ $tab==='reports'?'':'btn-ghost' }}" href="{{ route('waf.ui.headers.index', ['tab'=>'reports']) }}">CSP-Berichte</a>
    </div>
    @if($tab==='headers')
    <form method="POST" action="{{ route('waf.ui.headers.update') }}" class="card">
        @csrf @method('PUT')
        <div style="display:grid;gap:16px;grid-template-columns:1fr 1fr;">
            <div><label><input type="checkbox" name="hsts_enabled" value="1" @checked(data_get($config,'headers.hsts.enabled',true))> HSTS aktiv</label></div>
            <div><label>HSTS max-age (Sek.)</label><input type="number" name="hsts_max_age" min="0" value="{{ data_get($config,'headers.hsts.max_age',31536000) }}" style="width:100%;"></div>
            <div><label>X-Frame-Options</label><select name="x_frame_options" style="width:100%;"><option @selected(data_get($config,'headers.x_frame_options.value')==='SAMEORIGIN')>SAMEORIGIN</option><option @selected(data_get($config,'headers.x_frame_options.value')==='DENY')>DENY</option></select></div>
            <div><label>Referrer-Policy</label><input name="referrer_policy" value="{{ data_get($config,'headers.referrer_policy.value','strict-origin-when-cross-origin') }}" style="width:100%;"></div>
            <div><label><input type="checkbox" name="csp_enabled" value="1" @checked(data_get($config,'headers.csp.enabled',false))> Content-Security-Policy aktiv (mit Nonce pro Request)</label>
                 <label><input type="checkbox" name="csp_report_only" value="1" @checked(data_get($config,'headers.csp.report_only',true))> nur berichten (Report-Only)</label></div>
        </div>
        <p style="color:var(--muted);font-size:.85rem;margin-top:12px;">CSP-Direktiven werden aus der Config übernommen; Verstöße erscheinen im Reiter „CSP-Berichte". Report-Endpunkt: <code>POST /waf/csp-report</code>.</p>
        @if($canManage)<div style="margin-top:8px;"><button class="btn" type="submit">Speichern</button></div>@endif
    </form>
    @else
    <div class="card">
        @if($reports->isEmpty())<div class="empty">Keine CSP-Verstöße protokolliert.</div>@else
        <table><thead><tr><th>Datum</th><th>Direktive</th><th>Blockiert</th><th>Quelle</th><th>Anzahl</th></tr></thead><tbody>
            @foreach($reports as $r)<tr><td>{{ $r->received_at?->format('d.m.Y') }}</td><td><code>{{ $r->violated_directive }}</code></td>
                <td title="{{ $r->blocked_uri }}">{{ Str::limit($r->blocked_uri, 40) }}</td><td title="{{ $r->source_file }}">{{ Str::limit($r->source_file, 30) }}{{ $r->line ? ':'.$r->line : '' }}</td><td>{{ $r->count }}</td></tr>@endforeach
        </tbody></table>@endif
    </div>
    @endif
@endsection
