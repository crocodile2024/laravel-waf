@extends('waf::layouts.app')
@section('content')
    <form method="GET" class="card" style="display:flex;gap:12px;flex-wrap:wrap;align-items:end;">
        <div><label>Ergebnis</label>
            <select name="outcome">
                <option value="">alle</option>
                @foreach(['blocked'=>'Blockiert','challenged'=>'Challenge','logged'=>'Protokolliert','banned'=>'Gesperrt','allowed'=>'Erlaubt'] as $k=>$v)
                    <option value="{{ $k }}" @selected(($filters['outcome'] ?? '')===$k)>{{ $v }}</option>
                @endforeach
            </select></div>
        <div><label>IP</label><input name="ip" value="{{ $filters['ip'] ?? '' }}"></div>
        <div><label>Regel</label><input name="rule" value="{{ $filters['rule'] ?? '' }}" placeholder="WAF-SQLI-001"></div>
        <div><label>Pfad</label><input name="path" value="{{ $filters['path'] ?? '' }}"></div>
        <div><label>Vorfall-ID</label><input name="incident" value="{{ $filters['incident'] ?? '' }}"></div>
        <button class="btn" type="submit">Filtern</button>
        <a class="btn btn-ghost" href="{{ route('waf.ui.events.export', request()->query()) }}">CSV-Export</a>
    </form>

    <div class="card">
        @if($events->isEmpty())
            <div class="empty">Keine Ereignisse gefunden. Sobald die WAF Treffer erkennt, erscheinen sie hier.</div>
        @else
        <table>
            <thead><tr><th>Zeit</th><th>IP</th><th>Land</th><th>Methode</th><th>Pfad</th><th>Ergebnis</th><th>Status</th><th>Score</th><th></th></tr></thead>
            <tbody>
                @foreach($events as $event)
                    <tr>
                        <td>{{ $event->occurred_at?->format('d.m. H:i:s') }}</td>
                        <td><code>{{ $event->ip ?? $event->ip_hash }}</code></td>
                        <td>{{ $event->country }}</td>
                        <td>{{ $event->method }}</td>
                        <td title="{{ $event->path }}">{{ Str::limit($event->path, 40) }}</td>
                        <td>{{ $event->outcome }}</td>
                        <td>{{ $event->status_code }}</td>
                        <td>{{ $event->score }}</td>
                        <td><a href="{{ route('waf.ui.events.show', $event->id) }}">Details</a></td>
                    </tr>
                @endforeach
            </tbody>
        </table>
        {{ $events->links() }}
        @endif
    </div>
@endsection
