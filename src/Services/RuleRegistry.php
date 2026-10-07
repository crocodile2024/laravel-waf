<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Services;

use Crocodile2024\WAF\Engine\Rules\RuleCompiler;
use Crocodile2024\WAF\Engine\RuleSet;
use Crocodile2024\WAF\Models\Rule;
use Crocodile2024\WAF\Support\RedisStore;
use Throwable;

/**
 * Lädt, kompiliert, verteilt und liefert den Regelplan (RuleSet).
 *
 * Hot-Path: In-Process-Cache (statisch pro Worker/APCu) + Versionsabgleich über Redis.
 * Keine DB-Abfrage im Request, solange die Version unverändert ist.
 */
class RuleRegistry
{
    private static ?RuleSet $cached = null;

    private static ?int $cachedVersion = null;

    public function __construct(
        private readonly RedisStore $redis,
        private readonly RuleCompiler $compiler,
    ) {}

    /**
     * Liefert den aktuellen Regelplan; lädt bei Versionsabweichung neu.
     */
    public function current(): RuleSet
    {
        $version = $this->version();

        if (self::$cached !== null && self::$cachedVersion === $version && $version > 0) {
            return self::$cached;
        }

        if ($this->apcuEnabled()) {
            $apcuVersion = apcu_fetch($this->redis->key('rules:version'));
            if ($apcuVersion === $version && ($plan = apcu_fetch($this->redis->key('rules:plan'))) !== false) {
                self::$cached = RuleSet::fromArray($plan);
                self::$cachedVersion = $version;

                return self::$cached;
            }
        }

        $raw = $version > 0 ? $this->redis->get('rules:'.$version) : null;
        if ($raw !== null) {
            $plan = json_decode($raw, true);
            if (is_array($plan)) {
                return $this->store(RuleSet::fromArray($plan), $version);
            }
        }

        // Fallback: aus DB kompilieren (z. B. frischer Redis oder erster Request).
        return $this->compileFromDatabase();
    }

    public function version(): int
    {
        $v = $this->redis->get('rules:version');

        return $v !== null ? (int) $v : 0;
    }

    /**
     * Kompiliert alle aktiven Regeln aus der DB, legt den Plan in Redis ab,
     * erhöht die Version und verteilt sie per Pub/Sub (6.).
     */
    public function recompile(): RuleSet
    {
        $set = $this->buildFromDatabase($this->nextVersion());
        $this->persist($set);

        return $this->store($set, $set->version);
    }

    private function compileFromDatabase(): RuleSet
    {
        try {
            $version = $this->version();
            if ($version === 0) {
                return $this->recompile();
            }
            $set = $this->buildFromDatabase($version);
            $this->redis->set('rules:'.$version, $this->encode($set));

            return $this->store($set, $version);
        } catch (Throwable) {
            return $this->store(new RuleSet([], [], 0), 0);
        }
    }

    private function buildFromDatabase(int $version): RuleSet
    {
        $request = [];
        $response = [];

        Rule::query()->where('is_active', true)->orderBy('priority')->chunk(500, function ($rules) use (&$request, &$response): void {
            foreach ($rules as $rule) {
                try {
                    $compiled = $this->compiler->compile($rule->toDefinition());
                } catch (Throwable) {
                    continue;
                }
                if ($compiled['phase'] === 'response') {
                    $response[] = $compiled;
                } else {
                    $request[] = $compiled;
                }
            }
        });

        usort($request, static fn (array $a, array $b) => $a['priority'] <=> $b['priority']);
        usort($response, static fn (array $a, array $b) => $a['priority'] <=> $b['priority']);

        return new RuleSet($request, $response, $version);
    }

    private function persist(RuleSet $set): void
    {
        $this->redis->set('rules:'.$set->version, $this->encode($set));
        $this->redis->set('rules:version', (string) $set->version);
        $this->redis->publish('invalidate', 'rules:'.$set->version);
    }

    private function nextVersion(): int
    {
        $next = $this->redis->incr('rules:version:seq');

        return $next > 0 ? $next : (time());
    }

    private function store(RuleSet $set, int $version): RuleSet
    {
        self::$cached = $set;
        self::$cachedVersion = $version;
        if ($this->apcuEnabled() && $version > 0) {
            apcu_store($this->redis->key('rules:version'), $version, 300);
            apcu_store($this->redis->key('rules:plan'), $set->toArray(), 300);
        }

        return $set;
    }

    private function encode(RuleSet $set): string
    {
        return (string) json_encode($set->toArray(), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    private function apcuEnabled(): bool
    {
        return function_exists('apcu_enabled') && apcu_enabled();
    }

    /**
     * Setzt den In-Process-Cache zurück (Tests / Octane-Flush).
     */
    public static function resetCache(): void
    {
        self::$cached = null;
        self::$cachedVersion = null;
    }
}
