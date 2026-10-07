<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Http\Middleware;

use Closure;
use Crocodile2024\WAF\Services\ConfigManager;
use Crocodile2024\WAF\Support\CspNonce;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Response;

/**
 * Setzt Security-Header und härtet Cookies (5.11). Alles einzeln schaltbar.
 */
class SecurityHeaders
{
    public function __construct(
        private readonly ConfigManager $config,
        private readonly CspNonce $nonce,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);

        if (! $this->config->get('headers.enabled', true)) {
            return $response;
        }

        $this->applyCsp($response);
        $this->applySimpleHeaders($response);
        $this->hardenCookies($response);

        return $response;
    }

    private function applyCsp(Response $response): void
    {
        $csp = (array) $this->config->get('headers.csp', []);
        if (! ($csp['enabled'] ?? false)) {
            return;
        }

        $parts = [];
        foreach ((array) ($csp['directives'] ?? []) as $directive => $sources) {
            $sources = array_map(function (string $s): string {
                return $s === "'nonce'" ? "'nonce-".$this->nonce->value()."'" : $s;
            }, (array) $sources);
            $parts[] = $directive.' '.implode(' ', $sources);
        }
        if (($csp['report_uri'] ?? false)) {
            $parts[] = 'report-uri '.url('waf/csp-report');
        }
        if ($parts === []) {
            return;
        }

        $header = ($csp['report_only'] ?? true) ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy';
        $response->headers->set($header, implode('; ', $parts));
    }

    private function applySimpleHeaders(Response $response): void
    {
        $h = $response->headers;

        if ($hsts = (array) $this->config->get('headers.hsts', [])) {
            if (($hsts['enabled'] ?? false)) {
                $value = 'max-age='.(int) ($hsts['max_age'] ?? 31536000);
                if ($hsts['include_subdomains'] ?? false) {
                    $value .= '; includeSubDomains';
                }
                if ($hsts['preload'] ?? false) {
                    $value .= '; preload';
                }
                $h->set('Strict-Transport-Security', $value);
            }
        }

        $map = [
            'headers.x_content_type_options' => 'X-Content-Type-Options',
            'headers.x_frame_options' => 'X-Frame-Options',
            'headers.referrer_policy' => 'Referrer-Policy',
            'headers.permissions_policy' => 'Permissions-Policy',
            'headers.coop' => 'Cross-Origin-Opener-Policy',
            'headers.corp' => 'Cross-Origin-Resource-Policy',
        ];
        foreach ($map as $key => $headerName) {
            $cfg = (array) $this->config->get($key, []);
            if (($cfg['enabled'] ?? false) && isset($cfg['value'])) {
                $h->set($headerName, (string) $cfg['value']);
            }
        }

        if ($this->config->get('headers.remove_powered_by', true)) {
            $h->remove('X-Powered-By');
            header_remove('X-Powered-By');
        }
        if ($this->config->get('headers.remove_server', true)) {
            $h->remove('Server');
        }
    }

    private function hardenCookies(Response $response): void
    {
        $cfg = (array) $this->config->get('headers.cookies', []);
        if (! ($cfg['enabled'] ?? true)) {
            return;
        }
        $allowlist = array_map('strtolower', (array) ($cfg['http_only_allowlist'] ?? []));
        $sameSite = (string) ($cfg['same_site'] ?? 'lax');

        $cookies = $response->headers->getCookies();
        foreach ($cookies as $cookie) {
            $httpOnly = ($cfg['http_only'] ?? true) && ! in_array(strtolower($cookie->getName()), $allowlist, true);
            $response->headers->setCookie(new Cookie(
                $cookie->getName(),
                $cookie->getValue(),
                $cookie->getExpiresTime(),
                $cookie->getPath(),
                $cookie->getDomain(),
                ($cfg['secure'] ?? true) ? true : $cookie->isSecure(),
                $httpOnly,
                $cookie->isRaw(),
                $sameSite,
            ));
        }
    }
}
