<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Services;

use Crocodile2024\WAF\Models\Event;
use Crocodile2024\WAF\Models\StatHourly;
use Crocodile2024\WAF\Support\RedisStore;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

/**
 * Schreibt die Ereignis-Warteschlange gebündelt in die DB und aggregiert Statistiken (6.).
 */
class EventFlusher
{
    public function __construct(
        private readonly RedisStore $redis,
        private readonly ConfigManager $config,
    ) {}

    /**
     * @return int Anzahl geschriebener Ereignisse
     */
    public function flush(): int
    {
        $batchSize = (int) $this->config->get('events.flush_batch', 500);
        $total = 0;

        while (true) {
            $items = $this->redis->lpopMany('events:queue', $batchSize);
            if ($items === []) {
                break;
            }

            $rows = [];
            $statsBuckets = [];
            foreach ($items as $json) {
                $data = json_decode($json, true);
                if (! is_array($data)) {
                    continue;
                }
                $rows[] = $this->normalizeRow($data);
                $this->accumulateStats($statsBuckets, $data);
            }

            if ($rows !== []) {
                Event::query()->insert($rows);
                $total += count($rows);
            }
            $this->writeStats($statsBuckets);

            if (count($items) < $batchSize) {
                break;
            }
        }

        return $total;
    }

    /**
     * @param  array<string, mixed>  $data
     * @return array<string, mixed>
     */
    private function normalizeRow(array $data): array
    {
        return [
            'id' => $data['id'],
            'occurred_at' => $data['occurred_at'],
            'ip' => $data['ip'] ?? null,
            'ip_hash' => $data['ip_hash'] ?? '',
            'country' => $data['country'] ?? null,
            'asn' => $data['asn'] ?? null,
            'method' => $data['method'] ?? 'GET',
            'host' => $data['host'] ?? null,
            'path' => $data['path'] ?? '/',
            'route_name' => $data['route_name'] ?? null,
            'user_agent' => $data['user_agent'] ?? null,
            'user_id' => $data['user_id'] ?? null,
            'mode' => $data['mode'] ?? 'detect',
            'outcome' => $data['outcome'] ?? 'logged',
            'status_code' => $data['status_code'] ?? null,
            'score' => $data['score'] ?? 0,
            'matches' => json_encode($data['matches'] ?? [], JSON_UNESCAPED_UNICODE),
            'node' => $data['node'] ?? null,
            'anonymized_at' => null,
        ];
    }

    /**
     * @param  array<string, array<string, mixed>>  $buckets
     * @param  array<string, mixed>  $data
     */
    private function accumulateStats(array &$buckets, array $data): void
    {
        $hour = substr((string) $data['occurred_at'], 0, 13).':00:00';
        $outcome = (string) ($data['outcome'] ?? 'logged');
        $country = (string) ($data['country'] ?? '');

        $codes = [''];
        foreach ((array) ($data['matches'] ?? []) as $m) {
            $codes[] = (string) ($m['rule_code'] ?? '');
        }
        foreach (array_unique($codes) as $code) {
            $key = $hour.'|'.$outcome.'|'.$code.'|'.$country;
            if (! isset($buckets[$key])) {
                $buckets[$key] = ['hour' => $hour, 'outcome' => $outcome, 'rule_code' => $code, 'country' => $country, 'count' => 0];
            }
            $buckets[$key]['count']++;
        }
    }

    /**
     * @param  array<string, array<string, mixed>>  $buckets
     */
    private function writeStats(array $buckets): void
    {
        $driver = DB::connection()->getDriverName();
        foreach ($buckets as $bucket) {
            $attributes = [
                'hour' => $bucket['hour'],
                'outcome' => $bucket['outcome'],
                'rule_code' => $bucket['rule_code'],
                'country' => $bucket['country'],
            ];
            if ($driver === 'mysql' || $driver === 'mariadb') {
                DB::statement(
                    'INSERT INTO waf_stats_hourly (id, hour, outcome, rule_code, country, count) VALUES (?, ?, ?, ?, ?, ?)
                     ON DUPLICATE KEY UPDATE count = count + VALUES(count)',
                    [(string) Str::ulid(), $bucket['hour'], $bucket['outcome'], $bucket['rule_code'], $bucket['country'], $bucket['count']],
                );
            } else {
                $existing = StatHourly::query()->where($attributes)->first();
                if ($existing !== null) {
                    $existing->increment('count', (int) $bucket['count']);
                } else {
                    StatHourly::query()->create($attributes + ['count' => $bucket['count']]);
                }
            }
        }
    }
}
