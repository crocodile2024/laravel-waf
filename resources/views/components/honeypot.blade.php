{{-- Formular-Honeypot der WAF. Nicht entfernen. Für Menschen unsichtbar. --}}
<div aria-hidden="true" style="position:absolute;left:-9999px;top:-9999px;height:0;width:0;overflow:hidden;">
    <label for="waf_hp_field">Dieses Feld bitte leer lassen</label>
    <input type="text" id="waf_hp_field" name="waf_hp" value="" tabindex="-1" autocomplete="off">
</div>
<input type="hidden" name="waf_hp_token" value="{{ $token }}">
