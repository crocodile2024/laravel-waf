<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Services;

use Crocodile2024\WAF\Events\IpBanned;
use Crocodile2024\WAF\Events\IpUnbanned;
use Crocodile2024\WAF\Models\Ban;
use Crocodile2024\WAF\Support\Anonymizer;
use Crocodile2024\WAF\Support\IpMatcher;
use Crocodile2024\WAF\Support\RedisStore;
use Illuminate\Support\Facades\Event;

/**
 * Sperren (Bans) mit Eskalation. Redis = Hot-Path, DB = Persistenz/UI (5.6).
 */
class BanService
{
    public function __construct(
        private readonly RedisStore $redis,
        private readonly ConfigManager $config,
    ) {}

    private function ipv6Prefix(): int
    {
        return (int) $this->config->get('bans.ipv6_prefix', 64);
    }

    public function isBanned(string $ip): bool
    {
        $key = IpMatcher::key($ip, $this->ipv6Prefix());

        return $this->redis->exists('ban:'.$key);
    }

    public function activeUntil(string $ip): ?int
    {
        $key = IpMatcher::key($ip, $this->ipv6Prefix());
        $ttl = $this->redis->ttl('ban:'.$key);

        return $ttl > 0 ? time() + $ttl : null;
    }

    /**
     * Sperrt eine IP. Dauer wird – falls nicht angegeben – per Eskalation bestimmt.
     */
    public function ban(string $ip, ?int $minutes = null, string $reason = 'manuell', string $source = 'manual', ?string $ruleCode = null): Ban
    {
        $key = IpMatcher::key($ip, $this->ipv6Prefix());
        $level = $this->currentLevel($key);
        $minutes ??= $this->escalationMinutes($level);
        $until = now()->addMinutes($minutes);

        $this->redis->set('ban:'.$key, $reason, $minutes * 60);
        $this->bumpLevel($key);

        $ban = Ban::query()->create([
            'ip_key' => $key,
            'ip_hash' => Anonymizer::hash($key, $this->config->pepper()),
            'reason' => mb_substr($reason, 0, 255),
            'rule_code' => $ruleCode,
            'level' => $level + 1,
            'banned_until' => $until,
            'source' => $source,
        ]);

        Event::dispatch(new IpBanned($key, $until->getTimestamp(), $reason, $source));

        return $ban;
    }

    public function unban(string $ip, ?string $by = null): void
    {
        $key = IpMatcher::key($ip, $this->ipv6Prefix());
        $this->redis->del('ban:'.$key);

        Ban::query()->where('ip_key', $key)->whereNull('lifted_at')->update([
            'lifted_at' => now(),
            'lifted_by' => $by,
        ]);

        Event::dispatch(new IpUnbanned($key, $by));
    }

    private function currentLevel(string $key): int
    {
        $ttl = (int) ($this->config->get('bans.reset_after_days', 30)) * 86400;
        $value = $this->redis->get('banlevel:'.$key);

        return $value !== null ? (int) $value : 0;
    }

    private function bumpLevel(string $key): void
    {
        $ttl = (int) ($this->config->get('bans.reset_after_days', 30)) * 86400;
        $this->redis->incr('banlevel:'.$key, 1, $ttl);
    }

    private function escalationMinutes(int $level): int
    {
        /** @var array<int, int> $escalation */
        $escalation = (array) $this->config->get('bans.escalation', [15, 60, 1440, 10080]);
        $escalation = array_values($escalation);

        return (int) ($escalation[min($level, count($escalation) - 1)] ?? 15);
    }

    /**
     * Lädt aktive Bans aus der DB zurück nach Redis (waf:sync, 5.6).
     */
    public function syncFromDatabase(): int
    {
        $count = 0;
        Ban::query()->active()->chunkById(500, function ($bans) use (&$count): void {
            foreach ($bans as $ban) {
                $seconds = $ban->banned_until !== null ? now()->diffInSeconds($ban->banned_until, false) : 86400;
                if ($seconds > 0) {
                    $this->redis->set('ban:'.$ban->ip_key, $ban->reason, (int) $seconds);
                    $count++;
                }
            }
        });
        $this->redis->set('bans:loaded', '1');

        return $count;
    }
}
