@extends('waf::layouts.app')
@section('content')
    <form method="POST" action="{{ route('waf.ui.uploads.update') }}" class="card">
        @csrf @method('PUT')
        <div style="display:grid;gap:16px;grid-template-columns:1fr 1fr;">
            <div style="grid-column:1/3;"><label>Erlaubte Erweiterungen (kommagetrennt)</label>
                <input name="allowed_extensions" style="width:100%;" value="{{ implode(', ', (array) data_get($config,'uploads.allowed_extensions',[])) }}"></div>
            <div><label>Max. Dateigröße (MB)</label><input type="number" name="max_file_mb" min="1" value="{{ (int) (data_get($config,'uploads.max_file_bytes',20971520)/1048576) }}" style="width:100%;"></div>
            <div><label>Max. Dateien pro Request</label><input type="number" name="max_files" min="1" value="{{ data_get($config,'uploads.max_files',20) }}" style="width:100%;"></div>
            <div><label>Max. Kompressionsrate (ZIP-Bombe)</label><input type="number" name="max_compression_ratio" min="1" value="{{ data_get($config,'uploads.max_compression_ratio',100) }}" style="width:100%;"></div>
            <div><label><input type="checkbox" name="clamav_enabled" value="1" @checked(data_get($config,'clamav.enabled',false))> ClamAV-Prüfung aktiv</label>
                @if($clamavAvailable !== null)<div style="color:{{ $clamavAvailable ? '#10b981' : '#b91c1c' }};">ClamAV {{ $clamavAvailable ? 'erreichbar' : 'NICHT erreichbar' }}</div>@endif</div>
        </div>
        @if($canManage)<div style="margin-top:16px;"><button class="btn" type="submit">Speichern</button></div>@endif
    </form>
@endsection
