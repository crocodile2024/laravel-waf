@extends('waf::layouts.app')
@section('content')
    <div style="display:flex;gap:8px;margin-bottom:16px;">
        <a class="btn {{ $tab==='allow'?'':'btn-ghost' }}" href="{{ route('waf.ui.ip-lists.index', ['tab'=>'allow']) }}">Allowlist</a>
        <a class="btn {{ $tab==='deny'?'':'btn-ghost' }}" href="{{ route('waf.ui.ip-lists.index', ['tab'=>'deny']) }}">Denylist</a>
    </div>

    <div class="card">
        <h3 style="margin-top:0;">Ist eine IP betroffen?</h3>
        <form method="GET" style="display:flex;gap:8px;align-items:end;">
            <input type="hidden" name="tab" value="{{ $tab }}">
            <div><label>IP-Adresse</label><input name="lookup" value="{{ $lookup['ip'] ?? '' }}" placeholder="203.0.113.5"></div>
            <button class="btn" type="submit">Prüfen</button>
        </form>
        @if($lookup)
            <table style="margin-top:12px;">
                <tr><th>Allowlist</th><td>{{ $lookup['allow'] ?? '–' }}</td></tr>
                <tr><th>Denylist</th><td>{{ $lookup['deny'] ?? '–' }}</td></tr>
                <tr><th>Gesperrt</th><td>{{ $lookup['banned'] ? 'ja' : 'nein' }}</td></tr>
                <tr><th>Land / ASN</th><td>{{ $lookup['country'] ?? '–' }} / {{ $lookup['asn'] ?? '–' }}</td></tr>
            </table>
        @endif
    </div>

    @if($canManage)
    <div class="card">
        <h3 style="margin-top:0;">Eintrag hinzufügen ({{ $tab==='allow'?'Allowlist':'Denylist' }})</h3>
        <form method="POST" action="{{ route('waf.ui.ip-lists.store') }}" style="display:flex;gap:8px;flex-wrap:wrap;align-items:end;">
            @csrf
            <input type="hidden" name="list" value="{{ $tab }}">
            <div><label>IP / CIDR</label><input name="cidr" required placeholder="203.0.113.0/24"></div>
            <div><label>Kommentar</label><input name="comment"></div>
            <div><label>Läuft ab (optional)</label><input type="datetime-local" name="expires_at"></div>
            <label style="align-self:center;"><input type="checkbox" name="confirm_self" value="1"> Trotzdem sperren</label>
            <button class="btn" type="submit">Hinzufügen</button>
        </form>
        <details style="margin-top:12px;">
            <summary>Massenimport (eine IP/CIDR pro Zeile)</summary>
            <form method="POST" action="{{ route('waf.ui.ip-lists.import') }}" style="margin-top:8px;">
                @csrf
                <input type="hidden" name="list" value="{{ $tab }}">
                <textarea name="entries" rows="6" style="width:100%;font-family:'JetBrains Mono',monospace;" placeholder="10.0.0.0/8&#10;198.51.100.5"></textarea>
                <button class="btn" type="submit" style="margin-top:8px;">Importieren</button>
            </form>
        </details>
    </div>
    @endif

    <div class="card">
        @if($entries->isEmpty())
            <div class="empty">Keine Einträge in dieser Liste.</div>
        @else
        <table>
            <thead><tr><th>CIDR</th><th>Quelle</th><th>Kommentar</th><th>Läuft ab</th><th></th></tr></thead>
            <tbody>
                @foreach($entries as $entry)
                    <tr>
                        <td><code>{{ $entry->cidr }}</code></td><td>{{ $entry->source }}</td>
                        <td>{{ $entry->comment }}</td><td>{{ $entry->expires_at?->format('d.m.Y H:i') ?? '–' }}</td>
                        <td>@if($canManage)<form method="POST" action="{{ route('waf.ui.ip-lists.destroy', $entry) }}" style="display:inline;">@csrf @method('DELETE')<button class="btn btn-ghost" type="submit">Entfernen</button></form>@endif</td>
                    </tr>
                @endforeach
            </tbody>
        </table>
        {{ $entries->links() }}
        @endif
    </div>
@endsection
