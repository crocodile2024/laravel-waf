<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Services;

use Crocodile2024\WAF\Engine\RequestContext;
use Crocodile2024\WAF\Support\RedisStore;
use Illuminate\Support\Str;

/**
 * Proof-of-Work-Challenge und signiertes waf_pass-Cookie (5.9).
 *
 * Kein Drittanbieter, kein personenbezogenes Tracking. Der Pass bindet an
 * IP-Präfix + UA-Hash + Ablauf per HMAC.
 */
class ChallengeService
{
    public const COOKIE = 'waf_pass';

    public function __construct(
        private readonly RedisStore $redis,
        private readonly ConfigManager $config,
    ) {}

    public function difficulty(): int
    {
        return max(8, min(26, (int) $this->config->get('challenge.pow_difficulty', 18)));
    }

    /**
     * Erzeugt eine neue PoW-Aufgabe und speichert den erwarteten Zustand in Redis.
     *
     * @return array{nonce: string, difficulty: int}
     */
    public function issue(RequestContext $ctx): array
    {
        $nonce = Str::random(24);
        $ttl = (int) $this->config->get('challenge.nonce_ttl_seconds', 600);
        $this->redis->set('pow:'.$nonce, $this->bindKey($ctx), $ttl);

        return ['nonce' => $nonce, 'difficulty' => $this->difficulty()];
    }

    /**
     * Prüft die eingereichte Lösung (SHA-256(nonce|solution) mit führenden Null-Bits).
     */
    public function verify(RequestContext $ctx, string $nonce, string $solution): bool
    {
        if (! preg_match('/^[A-Za-z0-9]{1,64}$/', $nonce) || strlen($solution) > 64) {
            return false;
        }
        $stored = $this->redis->get('pow:'.$nonce);
        if ($stored === null || ! hash_equals($stored, $this->bindKey($ctx))) {
            return false;
        }
        $this->redis->del('pow:'.$nonce);

        $hash = hash('sha256', $nonce.'|'.$solution, true);

        return $this->leadingZeroBits($hash) >= $this->difficulty();
    }

    public function issuePass(RequestContext $ctx): string
    {
        $expires = time() + (int) $this->config->get('challenge.pass_ttl_hours', 12) * 3600;
        $payload = $this->bindKey($ctx).'|'.$expires;
        $sig = hash_hmac('sha256', $payload, $this->config->pepper());

        return base64_encode($expires.'.'.$sig);
    }

    public function hasValidPass(RequestContext $ctx): bool
    {
        $cookie = $ctx->cookies[self::COOKIE] ?? null;
        if (! is_string($cookie) || $cookie === '') {
            return false;
        }
        $decoded = base64_decode($cookie, true);
        if ($decoded === false || ! str_contains($decoded, '.')) {
            return false;
        }
        [$expires, $sig] = explode('.', $decoded, 2);
        if (! ctype_digit($expires) || (int) $expires < time()) {
            return false;
        }
        $expected = hash_hmac('sha256', $this->bindKey($ctx).'|'.$expires, $this->config->pepper());

        return hash_equals($expected, $sig);
    }

    private function bindKey(RequestContext $ctx): string
    {
        return $ctx->ipKey.'|'.substr(hash('sha256', $ctx->userAgent), 0, 16);
    }

    private function leadingZeroBits(string $binaryHash): int
    {
        $bits = 0;
        foreach (str_split($binaryHash) as $char) {
            $byte = ord($char);
            if ($byte === 0) {
                $bits += 8;

                continue;
            }
            for ($mask = 0x80; $mask > 0; $mask >>= 1) {
                if (($byte & $mask) === 0) {
                    $bits++;
                } else {
                    break 2;
                }
            }
        }

        return $bits;
    }
}
