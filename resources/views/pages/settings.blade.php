@extends('waf::layouts.app')
@section('content')
    <form method="POST" action="{{ route('waf.ui.settings.update') }}" class="card">
        @csrf @method('PUT')
        <div style="display:grid;gap:16px;grid-template-columns:1fr 1fr;">
            <div><label>Modus</label>
                <select name="mode" style="width:100%;">
                    @foreach($modes as $m)<option value="{{ $m->value }}" @selected(($config['mode']??'detect')===$m->value)>{{ $m->label() }}</option>@endforeach
                </select></div>
            <div><label>Paranoia-Level</label><input type="number" name="paranoia_level" min="1" max="4" value="{{ $config['paranoia_level'] ?? 1 }}" style="width:100%;"></div>
            <div><label>Inbound-Schwellwert</label><input type="number" name="inbound_threshold" min="1" value="{{ $config['inbound_threshold'] ?? 5 }}" style="width:100%;"></div>
            <div><label>Reputation-Halbwertszeit (Min.)</label><input type="number" name="reputation_half_life_minutes" min="1" value="{{ data_get($config,'reputation.half_life_minutes',60) }}" style="width:100%;"></div>
            <div><label>Ban-Schwellwert (Reputation)</label><input type="number" name="reputation_ban_threshold" min="1" value="{{ data_get($config,'reputation.ban_threshold',50) }}" style="width:100%;"></div>
            <div><label>Anonymisieren nach (Tagen)</label><input type="number" name="anonymize_after_days" min="0" value="{{ data_get($config,'privacy.anonymize_after_days',7) }}" style="width:100%;"></div>
            <div><label>Aufbewahrung Ereignisse (Tage)</label><input type="number" name="retention_days" min="1" value="{{ data_get($config,'privacy.retention_days',30) }}" style="width:100%;"></div>
            <div><label>Kontakt für Block-Seiten</label><input name="block_page_contact" value="{{ data_get($config,'block_page.contact') }}" style="width:100%;"></div>
        </div>
        <div style="margin-top:16px;">
            <label>Bestätigung (nur bei Modus „Aus" nötig: Wort BESTÄTIGEN eingeben)</label>
            <input name="confirm" placeholder="BESTÄTIGEN">
        </div>
        @if($canManage)
        <div style="margin-top:20px;"><button class="btn" type="submit">Speichern</button></div>
        @else
        <p style="color:var(--muted);margin-top:16px;">Nur-Lese-Zugriff – zum Ändern ist die Berechtigung „manageWAF" nötig.</p>
        @endif
    </form>
    <p style="color:var(--muted);font-size:.85rem;">Sicherheitskritische Schlüssel (Pepper, Redis, UI-Middleware, Gate, Fail-Modus) sind nur über die Konfiguration änderbar.</p>
@endsection
