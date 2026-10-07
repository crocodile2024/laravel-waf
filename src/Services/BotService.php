<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Services;

use Crocodile2024\WAF\Engine\RequestContext;
use Crocodile2024\WAF\Support\RedisStore;

/**
 * Bot-Prüfungen: Fallen-Routen, verifizierte Suchmaschinen-Bots, waf_pass-Cookie (5.9).
 */
class BotService
{
    private const SEARCH_ENGINES = [
        'googlebot' => ['.googlebot.com', '.google.com'],
        'bingbot' => ['.search.msn.com'],
        'applebot' => ['.applebot.apple.com'],
        'duckduckbot' => ['.duckduckgo.com'],
        'yandexbot' => ['.yandex.com', '.yandex.net', '.yandex.ru'],
    ];

    public function __construct(
        private readonly RedisStore $redis,
        private readonly ConfigManager $config,
        private readonly ChallengeService $challenge,
        private readonly ReputationService $reputation,
    ) {}

    public function hasValidPass(RequestContext $ctx): bool
    {
        return $this->challenge->hasValidPass($ctx);
    }

    /**
     * Prüft, ob der Pfad eine konfigurierte Fallen-Route ist.
     */
    public function trapRoute(RequestContext $ctx): ?string
    {
        $path = ltrim($ctx->path, '/');
        foreach ((array) $this->config->get('bots.trap_paths', []) as $trap) {
            $trap = ltrim((string) $trap, '/');
            if ($trap !== '' && ($path === $trap || \Illuminate\Support\Str::is($trap, $path))) {
                return $trap;
            }
        }

        return null;
    }

    /**
     * Prüft behauptete Suchmaschinen-Bots per Reverse-/Forward-DNS (Ergebnis 24 h gecacht).
     * Fälschung → Reputation +5.
     */
    public function applyScore(RequestContext $ctx): void
    {
        $ua = strtolower($ctx->userAgent);
        foreach (self::SEARCH_ENGINES as $bot => $suffixes) {
            if (str_contains($ua, $bot)) {
                if (! $this->config->get('bots.verify_search_engines', true)) {
                    return;
                }
                if (! $this->verifyBot($ctx->ip, $suffixes)) {
                    $this->reputation->add($ctx->ip, 5);
                }

                return;
            }
        }
    }

    /**
     * @param  array<int, string>  $suffixes
     */
    private function verifyBot(string $ip, array $suffixes): bool
    {
        $cacheKey = 'botverify:'.$ip;
        $cached = $this->redis->get($cacheKey);
        if ($cached !== null) {
            return $cached === '1';
        }

        $verified = $this->reverseForwardConfirm($ip, $suffixes);
        $this->redis->set($cacheKey, $verified ? '1' : '0', 86400);

        return $verified;
    }

    /**
     * @param  array<int, string>  $suffixes
     */
    private function reverseForwardConfirm(string $ip, array $suffixes): bool
    {
        $host = @gethostbyaddr($ip);
        if ($host === false || $host === $ip) {
            return false;
        }
        $host = strtolower($host);
        $match = false;
        foreach ($suffixes as $suffix) {
            if (str_ends_with($host, $suffix)) {
                $match = true;
                break;
            }
        }
        if (! $match) {
            return false;
        }

        // Forward-Bestätigung
        if (str_contains($ip, ':')) {
            $records = @dns_get_record($host, DNS_AAAA);
            foreach ($records ?: [] as $r) {
                if (isset($r['ipv6']) && inet_pton($r['ipv6']) === inet_pton($ip)) {
                    return true;
                }
            }

            return false;
        }

        return in_array($ip, @gethostbynamel($host) ?: [], true);
    }
}
