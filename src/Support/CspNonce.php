<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Support;

use Illuminate\Support\Str;

/**
 * Pro Request eine CSP-Nonce (Blade @wafNonce, Helper waf_nonce()).
 */
class CspNonce
{
    private ?string $nonce = null;

    public function value(): string
    {
        return $this->nonce ??= Str::random(24);
    }

    public function reset(): void
    {
        $this->nonce = null;
    }
}
