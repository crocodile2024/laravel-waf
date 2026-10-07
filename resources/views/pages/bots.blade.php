@extends('waf::layouts.app')
@section('content')
    <form method="POST" action="{{ route('waf.ui.bots.update') }}" class="card">
        @csrf @method('PUT')
        <div style="display:grid;gap:16px;grid-template-columns:1fr 1fr;">
            <div><label>Challenge-Typ</label><select name="challenge_type" style="width:100%;">
                <option value="pow" @selected(data_get($config,'challenge.type','pow')==='pow')>Proof-of-Work</option>
                <option value="captcha" @selected(data_get($config,'challenge.type')==='captcha')>Bild-Captcha (ohne JS)</option>
            </select></div>
            <div><label>PoW-Schwierigkeit (Bit)</label><input type="number" name="pow_difficulty" min="8" max="26" value="{{ data_get($config,'challenge.pow_difficulty',18) }}" style="width:100%;"></div>
            <div><label>Pass-Dauer (Stunden)</label><input type="number" name="pass_ttl_hours" min="1" value="{{ data_get($config,'challenge.pass_ttl_hours',12) }}" style="width:100%;"></div>
            <div><label><input type="checkbox" name="verify_search_engines" value="1" @checked(data_get($config,'bots.verify_search_engines',true))> Suchmaschinen-Bots per Reverse-DNS verifizieren</label>
                 <label><input type="checkbox" name="block_empty_user_agent" value="1" @checked(data_get($config,'bots.block_empty_user_agent',false))> Leeren User-Agent blockieren</label></div>
        </div>
        <div style="margin-top:16px;"><label>Fallen-Routen (eine pro Zeile) – Aufruf führt zu sofortigem Ban</label>
            <textarea name="trap_paths" rows="4" style="width:100%;font-family:'JetBrains Mono',monospace;">{{ implode("\n", (array) data_get($config,'bots.trap_paths',[])) }}</textarea></div>
        @if($canManage)<div style="margin-top:16px;"><button class="btn" type="submit">Speichern</button></div>@endif
    </form>
@endsection
