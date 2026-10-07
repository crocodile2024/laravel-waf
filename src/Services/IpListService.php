<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Services;

use Crocodile2024\WAF\Models\IpEntry;
use Crocodile2024\WAF\Support\IpMatcher;
use Crocodile2024\WAF\Support\IpSet;
use Crocodile2024\WAF\Support\RedisStore;
use Throwable;

/**
 * Allow-/Denylist (5.6). Kompilierte IpSets liegen in Redis (Hot-Path) und werden
 * per Versionsabgleich im Prozess zwischengespeichert.
 */
class IpListService
{
    /** @var array<string, IpSet> */
    private static array $cache = [];

    private static ?int $cacheVersion = null;

    public function __construct(
        private readonly RedisStore $redis,
        private readonly SettingsRepository $settings,
    ) {}

    public function isAllowed(string $ip): bool
    {
        return $this->set('allow')->contains($ip);
    }

    public function isDenied(string $ip): bool
    {
        return $this->set('deny')->contains($ip);
    }

    public function matchingEntry(string $list, string $ip): ?string
    {
        return $this->set($list)->match($ip);
    }

    private function set(string $list): IpSet
    {
        $version = $this->settings->version();
        if (self::$cacheVersion !== $version) {
            self::$cache = [];
            self::$cacheVersion = $version;
        }

        return self::$cache[$list] ??= $this->loadSet($list);
    }

    private function loadSet(string $list): IpSet
    {
        $raw = $this->redis->get('iplist:'.$list);
        if ($raw !== null) {
            $data = json_decode($raw, true);
            if (is_array($data)) {
                return IpSet::fromArray($data);
            }
        }

        return $this->rebuild($list);
    }

    public function rebuild(string $list): IpSet
    {
        try {
            $entries = IpEntry::query()->where('list', $list)->active()
                ->get(['id', 'cidr'])
                ->map(static fn (IpEntry $e) => ['cidr' => $e->cidr, 'id' => $e->id])
                ->all();
        } catch (Throwable) {
            $entries = [];
        }
        $set = IpSet::fromEntries($entries);
        $this->redis->set('iplist:'.$list, (string) json_encode($set->toArray(), JSON_UNESCAPED_SLASHES));

        return $set;
    }

    public function rebuildAll(): void
    {
        $this->rebuild('allow');
        $this->rebuild('deny');
        self::$cache = [];
    }

    /**
     * Legt einen Eintrag an (DB) und aktualisiert das Redis-Set.
     *
     * @return IpEntry
     */
    public function add(string $list, string $cidr, array $attributes = []): IpEntry
    {
        $parsed = IpMatcher::parse($cidr);
        if ($parsed === null) {
            throw new \InvalidArgumentException("Ungültige IP/CIDR: {$cidr}");
        }
        $entry = IpEntry::query()->create(array_merge([
            'list' => $list,
            'cidr' => $parsed['cidr'],
            'ip_start' => $parsed['start'],
            'ip_end' => $parsed['end'],
            'source' => 'manual',
        ], $attributes));

        $this->rebuild($list);
        self::$cache = [];

        return $entry;
    }

    public function remove(string $id): void
    {
        $entry = IpEntry::query()->find($id);
        if ($entry !== null) {
            $list = $entry->list;
            $entry->delete();
            $this->rebuild($list);
            self::$cache = [];
        }
    }

    public static function resetCache(): void
    {
        self::$cache = [];
        self::$cacheVersion = null;
    }
}
