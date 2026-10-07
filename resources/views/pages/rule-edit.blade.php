@extends('waf::layouts.app')
@section('content')
    <form method="POST" action="{{ $rule->exists ? route('waf.ui.rules.update', $rule) : route('waf.ui.rules.store') }}" class="card">
        @csrf
        @if($rule->exists)@method('PUT')@endif
        <div style="display:grid;gap:16px;grid-template-columns:1fr 1fr;">
            <div><label>Code</label><input name="code" value="{{ old('code', $rule->code) }}" required style="width:100%;"></div>
            <div><label>Name</label><input name="name" value="{{ old('name', $rule->name) }}" required style="width:100%;"></div>
            <div><label>Schwere</label>
                <select name="severity" style="width:100%;">
                    @foreach(['critical'=>'Kritisch','error'=>'Fehler','warning'=>'Warnung','notice'=>'Hinweis'] as $k=>$v)
                        <option value="{{ $k }}" @selected(old('severity',$rule->severity)===$k)>{{ $v }}</option>
                    @endforeach
                </select></div>
            <div><label>Paranoia-Level</label><input type="number" name="paranoia_level" min="1" max="4" value="{{ old('paranoia_level', $rule->paranoia_level ?? 1) }}" style="width:100%;"></div>
            <div><label>Priorität</label><input type="number" name="priority" min="0" max="1000" value="{{ old('priority', $rule->priority ?? 500) }}" style="width:100%;"></div>
            <div><label>Phase</label>
                <select name="phase" style="width:100%;">
                    <option value="request" @selected(old('phase',$rule->phase ?? 'request')==='request')>Request</option>
                    <option value="response" @selected(old('phase',$rule->phase)==='response')>Response</option>
                </select></div>
        </div>
        <div style="margin-top:16px;"><label>Beschreibung</label><textarea name="description" style="width:100%;" rows="2">{{ old('description', $rule->description) }}</textarea></div>
        <div style="margin-top:16px;"><label>Bedingungen (JSON)</label><textarea name="conditions" style="width:100%;font-family:'JetBrains Mono',monospace;" rows="6">{{ old('conditions', json_encode($rule->conditions ?? ['match'=>'any','items'=>[['target'=>'args.*','operator'=>'contains','value'=>'']]], JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES)) }}</textarea></div>
        <div style="margin-top:16px;"><label>Aktion (JSON)</label><textarea name="action" style="width:100%;font-family:'JetBrains Mono',monospace;" rows="3">{{ old('action', json_encode($rule->action ?? ['type'=>'block','status'=>403], JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES)) }}</textarea></div>
        <label style="margin-top:16px;"><input type="checkbox" name="is_active" value="1" @checked(old('is_active', $rule->is_active ?? true))> Aktiv</label>
        <div style="margin-top:20px;"><button class="btn" type="submit">Speichern</button> <a class="btn btn-ghost" href="{{ route('waf.ui.rules.index') }}">Abbrechen</a></div>
    </form>
@endsection
