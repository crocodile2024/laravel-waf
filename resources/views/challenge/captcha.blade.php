<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="robots" content="noindex, nofollow">
    <title>{{ trans('waf::waf.challenge.title', [], 'de') }}</title>
    <style {!! waf_nonce() !!}>
        :root { --bg:#f5f4f0; --fg:#1f2430; --primary:#4f46e5; --muted:#6b7280; --card:#fff; }
        body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
            background:var(--bg); color:var(--fg); font-family:'Plus Jakarta Sans',system-ui,sans-serif; padding:24px; }
        .card { background:var(--card); max-width:460px; width:100%; border-radius:16px; padding:40px; text-align:center;
            box-shadow:0 10px 40px rgba(31,36,48,.08); }
        h1 { font-family:'Instrument Serif',Georgia,serif; font-weight:400; font-size:1.8rem; margin:0 0 8px; }
        p { line-height:1.6; color:var(--muted); }
        img.captcha { margin:16px auto; display:block; border:1px solid rgba(31,36,48,.12); border-radius:8px; }
        input[type=text] { font:inherit; padding:10px 12px; border:1px solid rgba(31,36,48,.2); border-radius:8px; width:100%;
            text-align:center; letter-spacing:.3em; text-transform:uppercase; }
        button { font:inherit; margin-top:16px; padding:10px 20px; border:0; border-radius:9px; background:var(--primary); color:#fff; cursor:pointer; }
        .err { color:#b91c1c; }
        code { font-family:'JetBrains Mono',monospace; font-size:.8rem; color:var(--muted); }
        a { color:var(--primary); }
    </style>
</head>
<body>
    <main class="card">
        <h1>{{ trans('waf::waf.challenge.heading', [], 'de') }}</h1>
        <p>{{ trans('waf::waf.captcha.intro', [], 'de') }}</p>
        @if($errors->any())<p class="err">{{ trans('waf::waf.challenge.retry', [], 'de') }}</p>@endif
        <form method="POST" action="{{ route('waf.challenge.solve') }}">
            @csrf
            <input type="hidden" name="mode" value="captcha">
            <input type="hidden" name="token" value="{{ $token }}">
            <input type="hidden" name="target" value="{{ $target }}">
            <img class="captcha" src="{{ route('waf.challenge.captcha-image', ['token' => $token]) }}"
                 width="180" height="60" alt="{{ trans('waf::waf.captcha.alt', [], 'de') }}">
            <label for="answer">{{ trans('waf::waf.captcha.label', [], 'de') }}</label>
            <input type="text" id="answer" name="answer" autocomplete="off" autocapitalize="characters"
                   autocorrect="off" spellcheck="false" maxlength="12" required autofocus>
            <button type="submit">{{ trans('waf::waf.captcha.submit', [], 'de') }}</button>
        </form>
        @if(!empty($contact))
            <p style="margin-top:16px;font-size:.9rem;">{{ trans('waf::waf.captcha.contact_hint', [], 'de') }}
               <a href="mailto:{{ $contact }}">{{ $contact }}</a></p>
        @endif
        <p><code>{{ $incidentId }}</code></p>
    </main>
</body>
</html>
