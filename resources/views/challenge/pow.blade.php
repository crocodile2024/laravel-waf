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
        .card { background:var(--card); max-width:520px; width:100%; border-radius:16px; padding:40px; text-align:center;
            box-shadow:0 10px 40px rgba(31,36,48,.08); }
        h1 { font-family:'Instrument Serif',Georgia,serif; font-weight:400; font-size:1.8rem; margin:0 0 8px; }
        p { line-height:1.6; color:var(--muted); }
        .spinner { width:40px; height:40px; margin:24px auto; border:4px solid rgba(79,70,229,.2);
            border-top-color:var(--primary); border-radius:50%; animation:spin 1s linear infinite; }
        @keyframes spin { to { transform:rotate(360deg); } }
        code { font-family:'JetBrains Mono',monospace; font-size:.8rem; color:var(--muted); }
        noscript p { color:#b91c1c; }
    </style>
</head>
<body data-nonce="{{ waf_nonce() }}">
    <main class="card">
        <h1>{{ trans('waf::waf.challenge.heading', [], 'de') }}</h1>
        <p>{{ trans('waf::waf.challenge.intro', [], 'de') }}</p>
        <div class="spinner" id="waf-spinner" aria-hidden="true"></div>
        <p id="waf-status">{{ trans('waf::waf.challenge.working', [], 'de') }}</p>
        <noscript><p>{{ trans('waf::waf.challenge.nojs', [], 'de') }}</p></noscript>
        <p><code>{{ $incidentId }}</code></p>
        <form id="waf-form" method="POST" action="{{ route('waf.challenge.solve') }}">
            @csrf
            <input type="hidden" name="nonce" value="{{ $nonce }}">
            <input type="hidden" name="difficulty" value="{{ $difficulty }}">
            <input type="hidden" name="solution" id="waf-solution" value="">
            <input type="hidden" name="target" value="{{ $target }}">
        </form>
    </main>
    <script {!! waf_nonce() !!}>
        (function () {
            var nonce = {{ Illuminate\Support\Js::from($nonce) }};
            var difficulty = {{ (int) $difficulty }};
            var form = document.getElementById('waf-form');
            function fallback(){ form.submit(); }
            if (!window.Worker || !window.crypto || !crypto.subtle) { fallback(); return; }
            var src = "self.onmessage=async function(e){var n=e.data.n,d=e.data.d,s=0;" +
                "function lead(b){var c=0;for(var i=0;i<b.length;i++){var x=b[i];if(x===0){c+=8;continue;}" +
                "for(var m=128;m>0;m>>=1){if((x&m)===0)c++;else return c;}}return c;}" +
                "var enc=new TextEncoder();" +
                "while(true){var h=await crypto.subtle.digest('SHA-256',enc.encode(n+'|'+s));" +
                "if(lead(new Uint8Array(h))>=d){postMessage(String(s));return;}s++;}};";
            try {
                var w = new Worker(URL.createObjectURL(new Blob([src], {type:'application/javascript'})));
                w.onmessage = function (e) {
                    document.getElementById('waf-solution').value = e.data;
                    form.submit();
                };
                w.onerror = fallback;
                w.postMessage({n:nonce, d:difficulty});
            } catch (err) { fallback(); }
        })();
    </script>
</body>
</html>
