@extends('waf::layouts.app')
@section('content')
    <p><a href="{{ route('waf.ui.events.index') }}">← Zurück</a></p>
    <div class="card">
        <table>
            <tr><th>Vorfall-ID</th><td><code>{{ $event->id }}</code></td></tr>
            <tr><th>Zeitpunkt</th><td>{{ $event->occurred_at }}</td></tr>
            <tr><th>IP</th><td><code>{{ $event->ip ?? $event->ip_hash }}</code></td></tr>
            <tr><th>Land / ASN</th><td>{{ $event->country }} / {{ $event->asn }}</td></tr>
            <tr><th>Methode / Pfad</th><td>{{ $event->method }} <code>{{ $event->path }}</code></td></tr>
            <tr><th>Ergebnis</th><td>{{ $event->outcome }} ({{ $event->status_code }})</td></tr>
            <tr><th>Score</th><td>{{ $event->score }}</td></tr>
            <tr><th>Knoten</th><td>{{ $event->node }}</td></tr>
        </table>
    </div>
    <h2>Treffer</h2>
    <div class="card">
        @forelse($event->matches ?? [] as $match)
            <div style="padding:10px 0;border-bottom:1px solid var(--border);">
                <strong>{{ $match['rule_code'] ?? '' }}</strong> – {{ $match['rule_name'] ?? '' }}
                <div style="color:var(--muted);font-size:.85rem;">Ziel: {{ $match['target'] ?? '' }} · Parameter: {{ $match['parameter'] ?? '–' }}</div>
                @if($canViewPayloads && !empty($match['snippet']))
                    <pre style="background:var(--bg);padding:8px;border-radius:6px;overflow:auto;"><code>{{ $match['snippet'] }}</code></pre>
                @endif
            </div>
        @empty
            <div class="empty">Keine Treffer gespeichert.</div>
        @endforelse
    </div>
@endsection
