<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Services;

use Crocodile2024\WAF\Models\Setting;
use Crocodile2024\WAF\Support\RedisStore;
use Illuminate\Support\Arr;
use Throwable;

/**
 * Laufzeit-Konfiguration: waf_settings (DB/UI) überschreibt config/waf.php.
 *
 * Sicherheitskritische Schlüssel sind gegen Überschreiben per UI gesperrt.
 * Die zusammengeführte Konfiguration wird je Knoten in Redis zwischengespeichert
 * und per Versionsnummer invalidiert (Cluster, 6.).
 */
class SettingsRepository
{
    public const PROTECTED_KEYS = ['pepper', 'redis', 'ui.middleware', 'ui.gate', 'fail_mode', 'enabled'];

    /** @var array<string, mixed>|null */
    private ?array $merged = null;

    private ?int $loadedVersion = null;

    public function __construct(
        private readonly RedisStore $redis,
    ) {}

    /**
     * Aktuelle Config-Version (Garantie der Verteilung, 6.).
     */
    public function version(): int
    {
        $v = $this->redis->get('config:version');

        return $v !== null ? (int) $v : 0;
    }

    public function bumpVersion(): int
    {
        $v = $this->redis->incr('config:version');
        $this->redis->publish('invalidate', (string) $v);

        return $v;
    }

    public function get(string $key, mixed $default = null): mixed
    {
        return Arr::get($this->all(), $key, $default);
    }

    /**
     * @return array<string, mixed>
     */
    public function all(): array
    {
        $version = $this->version();
        if ($this->merged !== null && $this->loadedVersion === $version) {
            return $this->merged;
        }

        $this->loadedVersion = $version;

        return $this->merged = $this->buildMerged();
    }

    /**
     * Erzwingt Neuaufbau beim nächsten Zugriff (z. B. nach Octane-Request).
     */
    public function refresh(): void
    {
        $this->merged = null;
        $this->loadedVersion = null;
    }

    /**
     * Setzt einen UI-überschreibbaren Wert und erhöht die Config-Version.
     */
    public function set(string $key, mixed $value, ?string $by = null): void
    {
        if ($this->isProtected($key)) {
            throw new \InvalidArgumentException("Der Schlüssel „{$key}“ kann nur über die Konfiguration geändert werden.");
        }
        Setting::query()->updateOrCreate(
            ['key' => $key],
            ['value' => $value, 'updated_by' => $by, 'updated_at' => now()],
        );
        $this->bumpVersion();
        $this->refresh();
    }

    public function forget(string $key): void
    {
        Setting::query()->whereKey($key)->delete();
        $this->bumpVersion();
        $this->refresh();
    }

    public function isProtected(string $key): bool
    {
        foreach (self::PROTECTED_KEYS as $protected) {
            if ($key === $protected || str_starts_with($key, $protected.'.')) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return array<string, mixed>
     */
    private function buildMerged(): array
    {
        $config = (array) config('waf', []);

        try {
            $overrides = Setting::query()->pluck('value', 'key')->all();
        } catch (Throwable) {
            $overrides = [];
        }

        foreach ($overrides as $key => $value) {
            if ($this->isProtected((string) $key)) {
                continue;
            }
            Arr::set($config, (string) $key, $value);
        }

        return $config;
    }
}
