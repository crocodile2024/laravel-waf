<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Services;

use Crocodile2024\WAF\Engine\RequestContext;
use Crocodile2024\WAF\Engine\Rules\RuleMatch;

/**
 * Request-Grenzen (5.12): Methode, URL-/Header-/Parametergrenzen, Host-Allowlist.
 */
class LimitService
{
    public function __construct(
        private readonly ConfigManager $config,
        private readonly ProfileResolver $profiles,
    ) {}

    /**
     * @return array{code: string, match: RuleMatch}|null
     */
    public function check(RequestContext $ctx): ?array
    {
        $limits = $this->profiles->limitsFor($ctx);

        $methods = array_map('strtoupper', (array) ($limits['allowed_methods'] ?? []));
        if ($methods !== [] && ! in_array($ctx->method, $methods, true)) {
            return $this->hit('WAF-PROTO-001', 'method', $ctx->method, 'Unzulässige Methode');
        }

        if ($ctx->host === '' && $ctx->method !== 'OPTIONS') {
            return $this->hit('WAF-PROTO-010', 'header.host', '', 'Fehlender Host-Header');
        }

        $allowedHosts = (array) ($limits['allowed_hosts'] ?? []);
        if ($allowedHosts !== [] && ! in_array($ctx->host, array_map('strtolower', $allowedHosts), true)) {
            return $this->hit('WAF-PROTO-011', 'header.host', $ctx->host, 'Host nicht erlaubt (Host-Header-Injection)');
        }

        if (strlen($ctx->uri) > (int) ($limits['max_url_length'] ?? 4096)) {
            return $this->hit('WAF-PROTO-003', 'uri', '', 'URL zu lang');
        }
        if ($ctx->headerBytes > (int) ($limits['max_header_bytes'] ?? 8192)) {
            return $this->hit('WAF-PROTO-004', 'header', '', 'Header-Größe überschritten');
        }
        if ($ctx->headerCount > (int) ($limits['max_header_count'] ?? 100)) {
            return $this->hit('WAF-PROTO-005', 'header', '', 'Zu viele Header');
        }
        if ($ctx->paramCount() > (int) ($limits['max_params'] ?? 500)) {
            return $this->hit('WAF-PROTO-006', 'args', '', 'Zu viele Parameter');
        }
        if ($ctx->duplicateContentLength > 1) {
            return $this->hit('WAF-PROTO-007', 'header.content-length', '', 'Doppelter Content-Length-Header');
        }
        if ($ctx->bodyTooDeep) {
            return $this->hit('WAF-PROTO-002', 'body', '', 'Verschachtelung zu tief');
        }

        $maxParamLen = (int) ($limits['max_param_length'] ?? 65536);
        foreach ([...$ctx->query, ...$ctx->body] as $name => $value) {
            if (strlen($value) > $maxParamLen) {
                return $this->hit('WAF-PROTO-008', (string) $name, '', 'Parameterwert zu lang');
            }
        }

        $allowedTypes = (array) ($limits['allowed_content_types'] ?? []);
        if ($allowedTypes !== [] && $ctx->contentType !== '' && in_array($ctx->method, ['POST', 'PUT', 'PATCH'], true)) {
            $base = trim(explode(';', $ctx->contentType)[0]);
            if (! $this->contentTypeAllowed($base, $allowedTypes)) {
                return $this->hit('WAF-PROTO-009', 'header.content-type', $base, 'Content-Type nicht erlaubt');
            }
        }

        return null;
    }

    /**
     * @param  array<int, string>  $allowed
     */
    private function contentTypeAllowed(string $type, array $allowed): bool
    {
        foreach ($allowed as $pattern) {
            if (\Illuminate\Support\Str::is(strtolower($pattern), $type)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return array{code: string, match: RuleMatch}
     */
    private function hit(string $code, string $target, string $value, string $name): array
    {
        return [
            'code' => $code,
            'match' => new RuleMatch($code, $name, 'critical', 5, $target, null, $value, null, ['protocol']),
        ];
    }
}
