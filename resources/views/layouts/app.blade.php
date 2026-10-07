<!DOCTYPE html>
<html lang="de" data-theme="light">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <title>{{ $title ?? 'WAF' }} · WAF</title>
    @php($mode = app(\Crocodile2024\WAF\Services\ConfigManager::class)->mode())
    <link rel="stylesheet" href="{{ asset('vendor/waf/waf.css') }}" {!! waf_nonce() !!}>
    <style {!! waf_nonce() !!}>
        :root{--bg:#f5f4f0;--fg:#1f2430;--primary:#4f46e5;--muted:#6b7280;--card:#fff;--border:rgba(31,36,48,.08);}
        *{box-sizing:border-box;}
        body{margin:0;background:var(--bg);color:var(--fg);font-family:'Plus Jakarta Sans',system-ui,sans-serif;display:flex;min-height:100vh;}
        a{color:var(--primary);text-decoration:none;}
        h1,h2,h3{font-family:'Instrument Serif',Georgia,serif;font-weight:400;}
        .sidebar{width:240px;background:var(--card);border-right:1px solid var(--border);padding:20px 0;flex-shrink:0;}
        .sidebar .brand{font-family:'Instrument Serif',serif;font-size:1.4rem;padding:0 20px 16px;border-bottom:1px solid var(--border);}
        .sidebar nav a{display:block;padding:9px 20px;color:var(--fg);font-size:.92rem;}
        .sidebar nav a:hover,.sidebar nav a.active{background:var(--bg);color:var(--primary);border-left:3px solid var(--primary);padding-left:17px;}
        .main{flex:1;display:flex;flex-direction:column;min-width:0;}
        .topbar{background:var(--card);border-bottom:1px solid var(--border);padding:14px 24px;display:flex;align-items:center;justify-content:space-between;gap:12px;}
        .badge{display:inline-block;padding:4px 12px;border-radius:999px;font-size:.8rem;font-weight:600;color:#fff;}
        .badge-secondary{background:#9ca3af;} .badge-info{background:#3b82f6;} .badge-warning{background:#f59e0b;} .badge-success{background:#10b981;}
        .content{padding:24px;max-width:1200px;}
        .card{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:20px;margin-bottom:20px;}
        .grid{display:grid;gap:16px;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));}
        .metric{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:18px;}
        .metric .value{font-size:1.8rem;font-weight:700;}
        .metric .label{color:var(--muted);font-size:.85rem;}
        table{width:100%;border-collapse:collapse;font-size:.9rem;}
        th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--border);}
        th{color:var(--muted);font-weight:600;font-size:.8rem;text-transform:uppercase;letter-spacing:.04em;}
        code{font-family:'JetBrains Mono',monospace;font-size:.82rem;}
        .btn{display:inline-block;padding:8px 16px;border-radius:9px;background:var(--primary);color:#fff;border:0;cursor:pointer;font-size:.9rem;}
        .btn-ghost{background:transparent;color:var(--primary);border:1px solid var(--primary);}
        input,select,textarea{font:inherit;padding:8px 10px;border:1px solid var(--border);border-radius:8px;background:#fff;color:var(--fg);}
        label{display:block;font-size:.85rem;color:var(--muted);margin-bottom:4px;}
        .toast{background:#10b981;color:#fff;padding:12px 16px;border-radius:9px;margin-bottom:16px;}
        .alert{background:#fef2f2;color:#b91c1c;padding:12px 16px;border-radius:9px;margin-bottom:16px;border:1px solid #fecaca;}
        .empty{text-align:center;padding:48px 24px;color:var(--muted);}
        @media (max-width:720px){body{flex-direction:column;}.sidebar{width:100%;}}
        @media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#15171c;--fg:#e5e7eb;--card:#1e2128;--border:rgba(255,255,255,.08);--muted:#9ca3af;}}
    </style>
</head>
<body>
    <aside class="sidebar">
        <div class="brand">WAF</div>
        <nav>
            @php($r = fn($n) => request()->routeIs($n) ? 'active' : '')
            <a class="{{ $r('waf.ui.dashboard') }}" href="{{ route('waf.ui.dashboard') }}">Übersicht</a>
            <a class="{{ $r('waf.ui.events.*') }}" href="{{ route('waf.ui.events.index') }}">Ereignisse</a>
            <a class="{{ $r('waf.ui.rules.*') }}" href="{{ route('waf.ui.rules.index') }}">Regeln</a>
            <a class="{{ $r('waf.ui.exceptions.*') }}" href="{{ route('waf.ui.exceptions.index') }}">Ausnahmen</a>
            <a class="{{ $r('waf.ui.ip-lists.*') }}" href="{{ route('waf.ui.ip-lists.index') }}">IP-Listen</a>
            <a class="{{ $r('waf.ui.bans.*') }}" href="{{ route('waf.ui.bans.index') }}">Sperren</a>
            <a class="{{ $r('waf.ui.settings.*') }}" href="{{ route('waf.ui.settings.index') }}">Einstellungen</a>
            <a class="{{ $r('waf.ui.audit.*') }}" href="{{ route('waf.ui.audit.index') }}">Audit-Log</a>
        </nav>
    </aside>
    <div class="main">
        <div class="topbar">
            <strong>{{ $title ?? '' }}</strong>
            <span class="badge badge-{{ $mode->badge() }}">Modus: {{ $mode->label() }}</span>
        </div>
        <div class="content">
            @if(session('status'))<div class="toast">{{ session('status') }}</div>@endif
            @if($errors->any())<div class="alert">{{ $errors->first() }}</div>@endif
            @yield('content')
        </div>
    </div>
</body>
</html>
