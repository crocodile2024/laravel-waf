@extends('waf::layouts.app')
@section('content')
    @if($canManage)
        <p><a class="btn" href="{{ route('waf.ui.rules.create') }}">Eigene Regel anlegen</a></p>
    @endif

    <h2>Eigene Regeln</h2>
    <div class="card">
        @if($customRules->isEmpty())
            <div class="empty">Noch keine eigenen Regeln. Legen Sie eine an, um bekannte Lücken virtuell zu patchen.</div>
        @else
        <table>
            <thead><tr><th>Code</th><th>Name</th><th>Schwere</th><th>PL</th><th>Priorität</th><th>Aktiv</th><th></th></tr></thead>
            <tbody>
                @foreach($customRules as $rule)
                    <tr>
                        <td><code>{{ $rule->code }}</code></td><td>{{ $rule->name }}</td>
                        <td>{{ $rule->severity }}</td><td>{{ $rule->paranoia_level }}</td><td>{{ $rule->priority }}</td>
                        <td>{{ $rule->is_active ? 'ja' : 'nein' }}</td>
                        <td>@if($canManage)<a href="{{ route('waf.ui.rules.edit', $rule) }}">Bearbeiten</a>@endif</td>
                    </tr>
                @endforeach
            </tbody>
        </table>
        @endif
    </div>

    <h2>Kernregeln</h2>
    @foreach($coreRules as $module => $rules)
        <div class="card">
            <h3 style="margin-top:0;">{{ $module }}</h3>
            <table>
                <thead><tr><th>Code</th><th>Name</th><th>Schwere</th><th>PL</th><th>Aktiv</th><th></th></tr></thead>
                <tbody>
                    @foreach($rules as $rule)
                        <tr>
                            <td><code>{{ $rule->code }}</code></td><td>{{ $rule->name }}</td>
                            <td>{{ $rule->severity }}</td><td>{{ $rule->paranoia_level }}</td>
                            <td>{{ $rule->is_active ? 'ja' : 'nein' }}</td>
                            <td>
                                @if($canManage)
                                <form method="POST" action="{{ route('waf.ui.rules.toggle', $rule) }}" style="display:inline;">
                                    @csrf
                                    <button class="btn btn-ghost" type="submit">{{ $rule->is_active ? 'Deaktivieren' : 'Aktivieren' }}</button>
                                </form>
                                @endif
                            </td>
                        </tr>
                    @endforeach
                </tbody>
            </table>
        </div>
    @endforeach
@endsection
