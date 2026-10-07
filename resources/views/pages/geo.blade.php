@extends('waf::layouts.app')
@section('content')
    <div class="card">
        <strong>GeoIP-Status:</strong>
        @if($available) vorhanden ({{ $ageDays ?? '?' }} Tage alt) @else <span style="color:#b91c1c;">nicht konfiguriert – Geo-Funktionen deaktiviert. Hinterlegen Sie eine MMDB-Datei und führen Sie <code>waf:geoip:update</code> aus.</span> @endif
    </div>
    <form method="POST" action="{{ route('waf.ui.geo.update') }}" class="card" @disabled(!$available)>
        @csrf @method('PUT')
        <p style="color:var(--muted);">Länder als ISO-Codes (z. B. <code>DE AT CH</code>), ASN als Zahlen.</p>
        <div style="display:grid;gap:16px;grid-template-columns:1fr 1fr 1fr;">
            <div><label>Erlaubte Länder (Allowlist)</label><textarea name="allowed_countries" rows="4" style="width:100%;">{{ implode(' ', (array) data_get($config,'geoip.allowed_countries',[])) }}</textarea></div>
            <div><label>Gesperrte Länder (Denylist)</label><textarea name="denied_countries" rows="4" style="width:100%;">{{ implode(' ', (array) data_get($config,'geoip.denied_countries',[])) }}</textarea></div>
            <div><label>Gesperrte ASNs</label><textarea name="denied_asns" rows="4" style="width:100%;">{{ implode("\n", (array) data_get($config,'geoip.denied_asns',[])) }}</textarea></div>
        </div>
        @if($canManage)<div style="margin-top:16px;"><button class="btn" type="submit" @disabled(!$available)>Speichern</button></div>@endif
    </form>
@endsection
