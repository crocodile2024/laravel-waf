@extends('waf::layouts.app')
@section('content')
    <form method="GET" class="card" style="display:flex;gap:8px;align-items:end;">
        <div><label>Aktion</label><input name="action" value="{{ $filters['action'] ?? '' }}" placeholder="rule.update"></div>
        <div><label>Benutzer</label><input name="user" value="{{ $filters['user'] ?? '' }}"></div>
        <button class="btn" type="submit">Filtern</button>
    </form>
    <div class="card">
        @if($entries->isEmpty())
            <div class="empty">Keine Audit-Einträge.</div>
        @else
        <table>
            <thead><tr><th>Zeit</th><th>Benutzer</th><th>Aktion</th><th>Objekt</th><th>Änderungen</th></tr></thead>
            <tbody>
                @foreach($entries as $e)
                    <tr>
                        <td>{{ $e->created_at?->format('d.m.Y H:i:s') }}</td><td>{{ $e->user_id }}</td>
                        <td><code>{{ $e->action }}</code></td>
                        <td>{{ $e->subject_type }} {{ $e->subject_id ? '#'.$e->subject_id : '' }}</td>
                        <td><details><summary>anzeigen</summary><pre style="white-space:pre-wrap;font-size:.8rem;">{{ json_encode($e->changes, JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) }}</pre></details></td>
                    </tr>
                @endforeach
            </tbody>
        </table>
        {{ $entries->links() }}
        @endif
    </div>
@endsection
