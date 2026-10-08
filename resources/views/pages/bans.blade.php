@extends('waf::layouts.app')
@section('content')
    <div style="display:flex;gap:8px;margin-bottom:16px;">
        <a class="btn {{ $history?'btn-ghost':'' }}" href="{{ route('waf.ui.bans.index') }}">Aktive Sperren</a>
        <a class="btn {{ $history?'':'btn-ghost' }}" href="{{ route('waf.ui.bans.index', ['history'=>1]) }}">Verlauf</a>
    </div>

    @if($canManage && !$history)
    <div class="card">
        <form method="POST" action="{{ route('waf.ui.bans.store') }}" style="display:flex;gap:8px;flex-wrap:wrap;align-items:end;">
            @csrf
            <div><label>IP-Adresse</label><input name="ip" required></div>
            <div><label>Dauer (Minuten, leer = Eskalation)</label><input type="number" name="minutes" min="1"></div>
            <div><label>Grund</label><input name="reason"></div>
            <button class="btn" type="submit">Sperren</button>
        </form>
    </div>
    @endif

    <div class="card">
        @if($bans->isEmpty())
            <div class="empty">{{ $history ? 'Keine aufgehobenen Sperren im Verlauf.' : 'Aktuell keine aktiven Sperren.' }}</div>
        @else
        <form method="POST" action="{{ route('waf.ui.bans.destroy') }}">
            @csrf @method('DELETE')
            <table>
                <thead><tr><th>@if($canManage && !$history)<input type="checkbox" onclick="">@endif</th><th>IP-Schlüssel</th><th>Grund</th><th>Stufe</th><th>Bis</th><th>Quelle</th><th></th></tr></thead>
                <tbody>
                    @foreach($bans as $ban)
                        <tr>
                            <td>@if($canManage && !$history)<input type="checkbox" name="ip_key[]" value="{{ $ban->ip_key }}">@endif</td>
                            <td><code>{{ $ban->ip_key }}</code></td><td>{{ $ban->reason }}</td><td>{{ $ban->level }}</td>
                            <td>{{ $ban->banned_until?->format('d.m.Y H:i') ?? 'unbegrenzt' }}</td><td>{{ $ban->source }}</td>
                            <td>@if($canManage && !$history)<button class="btn btn-ghost" type="submit" name="single" value="{{ $ban->ip_key }}">Aufheben</button>@elseif($ban->lifted_at)aufgehoben {{ $ban->lifted_at->format('d.m.Y') }}@endif</td>
                        </tr>
                    @endforeach
                </tbody>
            </table>
            @if($canManage && !$history)<button class="btn" type="submit" style="margin-top:12px;">Ausgewählte aufheben</button>@endif
        </form>
        {{ $bans->links() }}
        @endif
    </div>
@endsection
