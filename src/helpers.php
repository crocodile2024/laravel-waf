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
