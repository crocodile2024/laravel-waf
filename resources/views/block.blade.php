<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="robots" content="noindex, nofollow">
    <title>{{ trans('waf::waf.block.title', [], 'de') }}</title>
    <style {!! waf_nonce() !!}>
        :root { --bg:#f5f4f0; --fg:#1f2430; --primary:#4f46e5; --muted:#6b7280; --card:#ffffff; }
        * { box-sizing:border-box; }
        body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
            background:var(--bg); color:var(--fg); font-family:'Plus Jakarta Sans',system-ui,-apple-system,Segoe UI,Roboto,sans-serif; padding:24px; }
        .card { background:var(--card); max-width:560px; width:100%; border-radius:16px; padding:40px;
            box-shadow:0 10px 40px rgba(31,36,48,.08); border:1px solid rgba(31,36,48,.06); }
        h1 { font-family:'Instrument Serif',Georgia,serif; font-weight:400; font-size:2rem; margin:0 0 8px; }
        p { line-height:1.6; color:var(--muted); margin:0 0 16px; }
        .meta { background:var(--bg); border-radius:10px; padding:16px; margin:24px 0; font-size:.95rem; }
        .meta div { display:flex; justify-content:space-between; padding:4px 0; }
        .meta code { font-family:'JetBrains Mono',ui-monospace,monospace; color:var(--primary); font-weight:600; }
        .badge { display:inline-block; width:44px; height:44px; border-radius:12px; background:var(--primary);
            margin-bottom:16px; position:relative; }
        .badge::after { content:'!'; color:#fff; font-weight:700; font-size:1.5rem; position:absolute; inset:0; display:flex; align-items:center; justify-content:center; }
        .contact { font-size:.9rem; }
        .contact a { color:var(--primary); }
    </style>
</head>
<body>
    <main class="card" role="alert">
        <div class="badge" aria-hidden="true"></div>
        <h1>{{ trans('waf::waf.block.heading', [], 'de') }}</h1>
        <p>{{ trans('waf::waf.block.intro', [], 'de') }}</p>
        <div class="meta">
            <div><span>{{ trans('waf::waf.block.incident', [], 'de') }}</span> <code>{{ $incidentId }}</code></div>
            <div><span>{{ trans('waf::waf.block.time', [], 'de') }}</span> <span>{{ now()->format('d.m.Y H:i:s') }}</span></div>
        </div>
        <p>{{ trans('waf::waf.block.contact_hint', [], 'de') }}</p>
        @if(!empty($contact))
            <p class="contact">{{ trans('waf::waf.block.contact', [], 'de') }}: <a href="mailto:{{ $contact }}">{{ $contact }}</a></p>
        @endif
    </main>
</body>
</html>
