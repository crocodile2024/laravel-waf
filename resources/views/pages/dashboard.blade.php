@extends('waf::layouts.app')
@section('content')
    @foreach($hints as $hint)
        <div class="alert" style="background:#fffbeb;color:#92400e;border-color:#fde68a;">{{ $hint }}</div>
    @endforeach

    <h2>Letzte 24 Stunden</h2>
    <div class="grid">
        <div class="metric"><div class="value">{{ number_format($metrics['24h']['checked']) }}</div><div class="label">Geprüfte Requests</div></div>
        <div class="metric"><div class="value">{{ number_format($metrics['24h']['blocked']) }}</div><div class="label">Blockiert</div></div>
        <div class="metric"><div class="value">{{ number_format($metrics['24h']['challenged']) }}</div><div class="label">Challenges</div></div>
        <div class="metric"><div class="value">{{ number_format($metrics['24h']['logged']) }}</div><div class="label">Protokolliert</div></div>
        <div class="metric"><div class="value">{{ number_format($metrics['bans']['active']) }}</div><div class="label">Aktive Sperren</div></div>
    </div>

    <h2>Systemstatus</h2>
    <div class="card">
        <table>
            <tr><th>Redis</th><td>{{ $system['redis'] ? 'erreichbar' : 'NICHT erreichbar' }}</td></tr>
            <tr><th>Warteschlange</th><td>{{ $system['queue_length'] }} Ereignisse</td></tr>
            <tr><th>Konfigurationsversion</th><td>{{ $system['config_version'] }}</td></tr>
            <tr><th>GeoIP</th><td>{{ $system['geoip_available'] ? 'vorhanden ('.($system['geoip_age_days'] ?? '?').' Tage alt)' : 'nicht konfiguriert' }}</td></tr>
            <tr><th>Knoten</th><td>{{ $system['nodes'] ? implode(', ', $system['nodes']) : '–' }}</td></tr>
        </table>
    </div>

    <h2>Kennzahlen (7 / 30 Tage)</h2>
    <div class="card">
        <table>
            <thead><tr><th>Zeitraum</th><th>Blockiert</th><th>Challenges</th><th>Protokolliert</th></tr></thead>
            <tbody>
                <tr><td>7 Tage</td><td>{{ number_format($metrics['7d']['blocked']) }}</td><td>{{ number_format($metrics['7d']['challenged']) }}</td><td>{{ number_format($metrics['7d']['logged']) }}</td></tr>
                <tr><td>30 Tage</td><td>{{ number_format($metrics['30d']['blocked']) }}</td><td>{{ number_format($metrics['30d']['challenged']) }}</td><td>{{ number_format($metrics['30d']['logged']) }}</td></tr>
            </tbody>
        </table>
    </div>

    {{-- Diagramme: nur mit gebündelten Assets; die darunter liegenden Tabellen bleiben
         als barrierefreie Alternative immer sichtbar. --}}
    <h2>Diagramme (7 Tage)</h2>
    <div x-data="wafDashboard" data-endpoint="{{ route('waf.ui.dashboard.data') }}">
        <div class="card">
            <h3 style="margin-top:0;">Zeitverlauf blockiert / protokolliert</h3>
            <div style="position:relative;height:260px;"><canvas id="waf-chart-timeline" role="img"
                aria-label="Zeitverlauf blockierter und protokollierter Anfragen"></canvas></div>
        </div>
        <div class="grid" style="grid-template-columns:repeat(auto-fill,minmax(280px,1fr));">
            <div class="card">
                <h3 style="margin-top:0;">Top-10 Regeln</h3>
                <div style="position:relative;height:240px;"><canvas id="waf-chart-rules" role="img" aria-label="Häufigste Regeltreffer"></canvas></div>
            </div>
            <div class="card">
                <h3 style="margin-top:0;">Top-10 Länder</h3>
                <div style="position:relative;height:240px;"><canvas id="waf-chart-countries" role="img" aria-label="Häufigste Herkunftsländer"></canvas></div>
            </div>
        </div>
    </div>
@endsection
