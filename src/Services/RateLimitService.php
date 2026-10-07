<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Services;

use Crocodile2024\WAF\Engine\RequestContext;
use Crocodile2024\WAF\Models\RateLimitProfile;
use Crocodile2024\WAF\Support\RedisStore;

/**
 * Redis-basiertes Rate-Limiting per GCRA (clusterweit konsistent, 5.8).
 *
 * GCRA erlaubt eine gleichmäßige Rate (limit/window) plus Burst, ohne
 * Fenstergrenzen-Sprünge.
 */
class RateLimitService
{
    /** @var array<int, array<string, mixed>>|null */
    private ?array $profiles = null;

    public function __construct(
        private readonly RedisStore $redis,
        private readonly ConfigManager $config,
    ) {}

    /**
     * Prüft ein benanntes Profil gegen den Kontext.
     *
     * @param  array<string, mixed>  $profile
     */
    public function hit(array $profile, RequestContext $ctx): RateLimitResult
    {
        $key = $this->buildKey($profile, $ctx);
        $limit = max(1, (int) $profile['limit']);
        $window = max(1, (int) $profile['window_seconds']);
        $burst = max(0, (int) ($profile['burst'] ?? 0));

        return $this->gcra('rl:'.$profile['name'].':'.$key, $limit, $window, $burst);
    }

    /**
     * GCRA-Kernlogik als atomares Lua-Skript.
     */
    public function gcra(string $key, int $limit, int $window, int $burst = 0): RateLimitResult
    {
        $emission = $window / $limit;           // Sekunden pro Anfrage
        $tolerance = $emission * ($limit + $burst);
        $now = microtime(true);

        $script = <<<'LUA'
local tat = tonumber(redis.call('GET', KEYS[1]) or ARGV[1])
local now = tonumber(ARGV[1])
local emission = tonumber(ARGV[2])
local tolerance = tonumber(ARGV[3])
if tat < now then tat = now end
local new_tat = tat + emission
local allow_at = new_tat - tolerance
if allow_at <= now then
  redis.call('SET', KEYS[1], new_tat, 'EX', math.ceil(tolerance) + 1)
  local remaining = math.floor((now - (new_tat - tolerance)) / emission)
  return {1, remaining, 0}
else
  local retry = math.ceil(allow_at - now)
  return {0, 0, retry}
end
LUA;
        $result = $this->redis->eval($script, [$key], [sprintf('%.4f', $now), sprintf('%.6f', $emission), sprintf('%.6f', $tolerance)]);

        if (! is_array($result)) {
            // Redis nicht verfügbar → gemäß fail_mode durchlassen (open) oder sperren (closed)
            return new RateLimitResult(! $this->config->failClosed(), $limit, $limit, 0, $window);
        }

        $allowed = (int) ($result[0] ?? 1) === 1;
        $remaining = (int) ($result[1] ?? 0);
        $retry = (int) ($result[2] ?? 0);

        return new RateLimitResult($allowed, $limit, $remaining, $retry, $window);
    }

    private function buildKey(array $profile, RequestContext $ctx): string
    {
        return match ($profile['key_type']) {
            'ip' => $ctx->ipKey,
            'ip+route' => $ctx->ipKey.'|'.($ctx->routeName() ?? $ctx->path),
            'user' => (string) ($ctx->userId() ?? $ctx->ipKey),
            'ip+user_agent' => $ctx->ipKey.'|'.substr(sha1($ctx->userAgent), 0, 12),
            'header' => (string) ($ctx->header((string) ($profile['key_header'] ?? '')) ?? $ctx->ipKey),
            default => $ctx->ipKey,
        };
    }

    /**
     * Prüft einen einfachen Sliding-Counter (für 404-/Fehler-Fluten).
     */
    public function countInWindow(string $key, int $window): int
    {
        return $this->redis->incr('cnt:'.$key, 1, $window);
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    public function activeProfiles(): array
    {
        return $this->profiles ??= RateLimitProfile::query()->where('is_active', true)->get()
            ->map(static fn (RateLimitProfile $p) => [
                'name' => $p->name,
                'key_type' => $p->key_type,
                'key_header' => $p->key_header,
                'limit' => $p->limit,
                'window_seconds' => $p->window_seconds,
                'burst' => $p->burst,
                'action' => $p->action,
            ])->all();
    }
}
