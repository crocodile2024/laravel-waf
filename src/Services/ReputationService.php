<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Services;

use Crocodile2024\WAF\Support\IpMatcher;
use Crocodile2024\WAF\Support\RedisStore;

/**
 * IP-Reputationsscore mit exponentiellem Zerfall (Halbwertszeit konfigurierbar, 5.3).
 *
 * Gespeichert als (score, timestamp). Beim Lesen/Schreiben wird der Zerfall angewandt.
 */
class ReputationService
{
    public function __construct(
        private readonly RedisStore $redis,
        private readonly ConfigManager $config,
    ) {}

    /**
     * Fügt Punkte hinzu und liefert den aktuellen (zerfallenen) Score.
     */
    public function add(string $ip, int $points): float
    {
        $key = 'rep:'.IpMatcher::key($ip, (int) $this->config->get('bans.ipv6_prefix', 64));
        $halfLife = max(1, (int) $this->config->get('reputation.half_life_minutes', 60)) * 60;
        $now = microtime(true);

        $script = <<<'LUA'
local raw = redis.call('GET', KEYS[1])
local score = 0.0
local last = tonumber(ARGV[2])
if raw then
  local sep = string.find(raw, ':')
  if sep then
    score = tonumber(string.sub(raw, 1, sep - 1)) or 0.0
    last = tonumber(string.sub(raw, sep + 1)) or last
  end
end
local dt = tonumber(ARGV[2]) - last
if dt < 0 then dt = 0 end
score = score * math.pow(0.5, dt / tonumber(ARGV[3]))
score = score + tonumber(ARGV[1])
redis.call('SET', KEYS[1], string.format('%.4f', score) .. ':' .. ARGV[2], 'EX', tonumber(ARGV[4]))
return tostring(score)
LUA;
        $ttl = $halfLife * 10;
        $result = $this->redis->eval($script, [$key], [$points, sprintf('%.3f', $now), $halfLife, $ttl]);

        return is_numeric($result) ? (float) $result : 0.0;
    }

    public function score(string $ip): float
    {
        $key = 'rep:'.IpMatcher::key($ip, (int) $this->config->get('bans.ipv6_prefix', 64));
        $raw = $this->redis->get($key);
        if ($raw === null || ! str_contains($raw, ':')) {
            return 0.0;
        }
        [$score, $last] = explode(':', $raw, 2);
        $halfLife = max(1, (int) $this->config->get('reputation.half_life_minutes', 60)) * 60;
        $dt = max(0.0, microtime(true) - (float) $last);

        return (float) $score * (0.5 ** ($dt / $halfLife));
    }

    public function banThreshold(): int
    {
        return (int) $this->config->get('reputation.ban_threshold', 50);
    }

    public function reset(string $ip): void
    {
        $this->redis->del('rep:'.IpMatcher::key($ip, (int) $this->config->get('bans.ipv6_prefix', 64)));
    }
}
