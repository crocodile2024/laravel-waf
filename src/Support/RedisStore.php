<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Support;

use Illuminate\Contracts\Redis\Factory as RedisFactory;
use Illuminate\Redis\Connections\Connection;
use Illuminate\Support\Facades\Log;
use Throwable;

/**
 * Redis-Zugriffsschicht der WAF.
 *
 * Alle Schlüssel erhalten das Präfix aus `waf.redis.prefix`. Fehler werden
 * abgefangen, protokolliert und als "nicht verfügbar" markiert; der Aufrufer
 * entscheidet anhand von `fail_mode`, wie weiter verfahren wird.
 */
class RedisStore
{
    private ?Connection $connection = null;

    private bool $failed = false;

    private ?float $retryAt = null;

    public function __construct(
        private readonly RedisFactory $redis,
        private readonly string $connectionName,
        private readonly string $prefix,
    ) {}

    public function key(string $key): string
    {
        return $this->prefix.$key;
    }

    public function prefix(): string
    {
        return $this->prefix;
    }

    public function failed(): bool
    {
        return $this->failed;
    }

    /**
     * Setzt den Fehlerstatus zurück (z. B. zu Beginn eines neuen Requests unter Octane).
     */
    public function resetFailure(): void
    {
        if ($this->retryAt === null || microtime(true) >= $this->retryAt) {
            $this->failed = false;
            $this->retryAt = null;
        }
    }

    public function connection(): Connection
    {
        if ($this->connection === null) {
            /** @var Connection $connection */
            $connection = $this->redis->connection($this->connectionName);
            $this->connection = $connection;
        }

        return $this->connection;
    }

    /**
     * Führt eine Redis-Operation aus; bei Fehlern wird $default zurückgegeben.
     *
     * @template T
     *
     * @param  callable(Connection): T  $callback
     * @param  T  $default
     * @return T
     */
    public function attempt(callable $callback, mixed $default = null): mixed
    {
        if ($this->failed) {
            return $default;
        }

        try {
            return $callback($this->connection());
        } catch (Throwable $e) {
            $this->markFailed($e);

            return $default;
        }
    }

    public function markFailed(Throwable $e): void
    {
        if (! $this->failed) {
            Log::warning('[WAF] Redis nicht erreichbar: '.$e->getMessage());
        }
        $this->failed = true;
        // Unter langlebigen Workern nicht bei jedem Request erneut in den Timeout laufen.
        $this->retryAt = microtime(true) + 5;
        $this->connection = null;
    }

    public function ping(): bool
    {
        try {
            $this->connection()->command('ping');
            $this->failed = false;

            return true;
        } catch (Throwable $e) {
            $this->markFailed($e);

            return false;
        }
    }

    public function get(string $key): ?string
    {
        $value = $this->attempt(fn (Connection $c) => $c->command('get', [$this->key($key)]));

        return is_string($value) ? $value : null;
    }

    public function set(string $key, string $value, ?int $ttlSeconds = null): bool
    {
        return (bool) $this->attempt(function (Connection $c) use ($key, $value, $ttlSeconds) {
            if ($ttlSeconds !== null && $ttlSeconds > 0) {
                return $c->command('setex', [$this->key($key), $ttlSeconds, $value]);
            }

            return $c->command('set', [$this->key($key), $value]);
        }, false);
    }

    public function del(string ...$keys): int
    {
        if ($keys === []) {
            return 0;
        }

        return (int) $this->attempt(fn (Connection $c) => $c->command('del', array_map($this->key(...), $keys)), 0);
    }

    public function exists(string $key): bool
    {
        return (int) $this->attempt(fn (Connection $c) => $c->command('exists', [$this->key($key)]), 0) > 0;
    }

    public function incr(string $key, int $by = 1, ?int $ttlSeconds = null): int
    {
        return (int) $this->attempt(function (Connection $c) use ($key, $by, $ttlSeconds) {
            $value = $c->command('incrby', [$this->key($key), $by]);
            if ($ttlSeconds !== null && (int) $value === $by) {
                $c->command('expire', [$this->key($key), $ttlSeconds]);
            }

            return $value;
        }, 0);
    }

    public function ttl(string $key): int
    {
        return (int) $this->attempt(fn (Connection $c) => $c->command('ttl', [$this->key($key)]), -2);
    }

    public function rpush(string $key, string $value): int
    {
        return (int) $this->attempt(fn (Connection $c) => $c->command('rpush', [$this->key($key), $value]), 0);
    }

    public function llen(string $key): int
    {
        return (int) $this->attempt(fn (Connection $c) => $c->command('llen', [$this->key($key)]), 0);
    }

    /**
     * Entnimmt bis zu $count Elemente atomar vom Anfang der Liste.
     *
     * @return array<int, string>
     */
    public function lpopMany(string $key, int $count): array
    {
        $script = <<<'LUA'
local items = redis.call('LRANGE', KEYS[1], 0, tonumber(ARGV[1]) - 1)
if #items > 0 then
  redis.call('LTRIM', KEYS[1], #items, -1)
end
return items
LUA;
        $result = $this->eval($script, [$key], [$count]);

        return is_array($result) ? array_values(array_map('strval', $result)) : [];
    }

    public function publish(string $channel, string $message): void
    {
        $this->attempt(fn (Connection $c) => $c->command('publish', [$this->key($channel), $message]));
    }

    /**
     * Führt ein Lua-Skript aus. Schlüssel werden automatisch mit Präfix versehen.
     *
     * @param  array<int, string>  $keys
     * @param  array<int, scalar>  $args
     */
    public function eval(string $script, array $keys, array $args = []): mixed
    {
        return $this->attempt(function (Connection $c) use ($script, $keys, $args) {
            $prefixed = array_map($this->key(...), $keys);

            return $c->eval($script, count($prefixed), ...$prefixed, ...$args);
        });
    }

    /**
     * @return array<string, string>
     */
    public function hgetall(string $key): array
    {
        $result = $this->attempt(fn (Connection $c) => $c->command('hgetall', [$this->key($key)]), []);

        return is_array($result) ? $result : [];
    }

    /**
     * @param  array<string, scalar>  $values
     */
    public function hmset(string $key, array $values, ?int $ttlSeconds = null): void
    {
        $this->attempt(function (Connection $c) use ($key, $values, $ttlSeconds) {
            foreach ($values as $field => $value) {
                $c->command('hset', [$this->key($key), $field, (string) $value]);
            }
            if ($ttlSeconds !== null) {
                $c->command('expire', [$this->key($key), $ttlSeconds]);
            }
        });
    }

    public function sadd(string $key, string ...$members): void
    {
        if ($members !== []) {
            $this->attempt(fn (Connection $c) => $c->command('sadd', [$this->key($key), ...$members]));
        }
    }

    public function srem(string $key, string ...$members): void
    {
        if ($members !== []) {
            $this->attempt(fn (Connection $c) => $c->command('srem', [$this->key($key), ...$members]));
        }
    }

    /**
     * @return array<int, string>
     */
    public function smembers(string $key): array
    {
        $result = $this->attempt(fn (Connection $c) => $c->command('smembers', [$this->key($key)]), []);

        return is_array($result) ? array_values(array_map('strval', $result)) : [];
    }

    /**
     * Mehrere Schlüssel auf einmal lesen.
     *
     * @param  array<int, string>  $keys
     * @return array<int, string|null>
     */
    public function mget(array $keys): array
    {
        if ($keys === []) {
            return [];
        }
        $result = $this->attempt(fn (Connection $c) => $c->command('mget', [array_map($this->key(...), $keys)]), []);
        if (! is_array($result)) {
            return array_fill(0, count($keys), null);
        }

        return array_map(static fn ($v) => is_string($v) ? $v : null, array_values($result));
    }

    /**
     * Löscht alle WAF-Schlüssel dieses Präfixes (nur für Tests/Wartung).
     */
    public function flushPrefix(): void
    {
        $this->eval(<<<'LUA'
local cursor = '0'
repeat
  local r = redis.call('SCAN', cursor, 'MATCH', ARGV[1], 'COUNT', 1000)
  cursor = r[1]
  for _, k in ipairs(r[2]) do redis.call('DEL', k) end
until cursor == '0'
return 1
LUA, [], [$this->connectionPrefix().$this->prefix.'*']);
    }

    /**
     * Präfix der Laravel-Redis-Verbindung (database.redis.options.prefix), falls gesetzt.
     */
    private function connectionPrefix(): string
    {
        $prefix = config('database.redis.options.prefix');

        return is_string($prefix) ? $prefix : '';
    }
}
