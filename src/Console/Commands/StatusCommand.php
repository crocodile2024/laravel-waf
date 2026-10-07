<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Console\Commands;

use Crocodile2024\WAF\Models\Ban;
use Crocodile2024\WAF\Services\ConfigManager;
use Crocodile2024\WAF\Services\GeoIpService;
use Crocodile2024\WAF\Services\RuleRegistry;
use Crocodile2024\WAF\Support\RedisStore;
use Illuminate\Console\Command;

class StatusCommand extends Command
{
    protected $signature = 'waf:status';

    protected $description = 'Zeigt Modus, Regelversion, Redis-/GeoIP-Status, aktive Bans und Knoten.';

    public function handle(ConfigManager $config, RedisStore $redis, RuleRegistry $rules, GeoIpService $geo): int
    {
        $redisOk = $redis->ping();
        $this->table(['Eigenschaft', 'Wert'], [
            ['Modus', $config->mode()->label()],
            ['Paranoia-Level', (string) $config->paranoiaLevel()],
            ['Inbound-Schwellwert', (string) $config->inboundThreshold()],
            ['Fail-Modus', $config->failClosed() ? 'closed' : 'open'],
            ['Redis', $redisOk ? 'erreichbar' : 'NICHT erreichbar'],
            ['Regelversion', (string) $rules->version()],
            ['Ereigniswarteschlange', $redisOk ? (string) $redis->llen('events:queue') : '-'],
            ['GeoIP', $geo->available() ? ('vorhanden ('.($geo->databaseAgeDays() ?? '?').' Tage alt)') : 'nicht konfiguriert'],
            ['Aktive Bans (DB)', (string) Ban::query()->active()->count()],
        ]);

        $nodes = $redisOk ? $redis->smembers('nodes') : [];
        if ($nodes !== []) {
            $this->line('Knoten: '.implode(', ', $nodes));
        }

        return self::SUCCESS;
    }
}
