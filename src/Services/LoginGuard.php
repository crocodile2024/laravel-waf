<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Services;

use Crocodile2024\WAF\Support\Anonymizer;
use Crocodile2024\WAF\Support\IpMatcher;
use Crocodile2024\WAF\Support\RedisStore;

/**
 * Login-Bruteforce-Schutz (5.8): zählt fehlgeschlagene Logins je IP und je
 * (gehashter) Benutzerkennung. Ab Schwelle Challenge, danach Ban.
 */
class LoginGuard
{
    public function __construct(
        private readonly RedisStore $redis,
        private readonly ConfigManager $config,
        private readonly BanService $bans,
        private readonly ReputationService $reputation,
    ) {}

    public function enabled(): bool
    {
        return (bool) $this->config->get('rate_limit.login.enabled', true);
    }

    /**
     * Registriert einen fehlgeschlagenen Login. Die Benutzerkennung wird nur
     * gehasht gespeichert (DSGVO).
     */
    public function recordFailure(string $ip, ?string $identifier): void
    {
        if (! $this->enabled()) {
            return;
        }

        $window = (int) $this->config->get('rate_limit.login.window_seconds', 900);
        $challengeAfter = (int) $this->config->get('rate_limit.login.challenge_after', 5);
        $banAfter = (int) $this->config->get('rate_limit.login.ban_after', 15);

        $ipKey = IpMatcher::key($ip, (int) $this->config->get('bans.ipv6_prefix', 64));
        $count = $this->redis->incr('login:ip:'.$ipKey, 1, $window);

        if ($identifier !== null && $identifier !== '') {
            $idHash = Anonymizer::hashIdentifier($identifier, $this->config->pepper());
            $this->redis->incr('login:id:'.$idHash, 1, $window);
        }

        if ($banAfter > 0 && $count >= $banAfter) {
            $this->bans->ban($ip, null, 'Login-Bruteforce', 'auto');
        } elseif ($challengeAfter > 0 && $count >= $challengeAfter) {
            // Markiert die IP für eine Challenge beim nächsten HTML-Request.
            $this->redis->set('login:challenge:'.$ipKey, '1', $window);
            $this->reputation->add($ip, 2);
        }
    }

    public function shouldChallenge(string $ip): bool
    {
        $ipKey = IpMatcher::key($ip, (int) $this->config->get('bans.ipv6_prefix', 64));

        return $this->redis->exists('login:challenge:'.$ipKey);
    }

    public function clear(string $ip): void
    {
        $ipKey = IpMatcher::key($ip, (int) $this->config->get('bans.ipv6_prefix', 64));
        $this->redis->del('login:ip:'.$ipKey, 'login:challenge:'.$ipKey);
    }
}
