<?php

declare(strict_types=1);

use Crocodile2024\WAF\Support\CspNonce;

if (! function_exists('waf_nonce')) {
    /**
     * Liefert die CSP-Nonce des aktuellen Requests.
     */
    function waf_nonce(): string
    {
        return app(CspNonce::class)->value();
    }
}

if (! function_exists('waf_asset')) {
    /**
     * Löst einen gebündelten Asset-Eintrag über das Vite-Manifest auf.
     *
     * Erwartet veröffentlichte Assets unter public/vendor/waf/ (via
     * `vendor:publish --tag=waf-assets`). Liefert null, wenn nicht vorhanden.
     */
    function waf_asset(string $entry = 'resources/js/waf.js', string $kind = 'file'): ?string
    {
        static $manifest = null;
        if ($manifest === null) {
            $path = public_path('vendor/waf/manifest.json');
            $manifest = is_file($path) ? (json_decode((string) file_get_contents($path), true) ?: []) : [];
        }
        $node = $manifest[$entry] ?? null;
        if (! is_array($node)) {
            return null;
        }
        if ($kind === 'css') {
            $css = $node['css'][0] ?? null;

            return is_string($css) ? asset('vendor/waf/'.$css) : null;
        }

        return isset($node['file']) ? asset('vendor/waf/'.$node['file']) : null;
    }
}
