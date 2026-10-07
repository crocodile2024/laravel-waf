<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Services;

use Crocodile2024\WAF\Engine\Mode;

/**
 * Typisierter Zugriff auf die zusammengeführte WAF-Konfiguration.
 */
class ConfigManager
{
    public function __construct(
        private readonly SettingsRepository $settings,
    ) {}

    public function settings(): SettingsRepository
    {
        return $this->settings;
    }

    public function get(string $key, mixed $default = null): mixed
    {
        return $this->settings->get($key, $default);
    }

    public function enabled(): bool
    {
        return (bool) config('waf.enabled', true);
    }

    public function mode(): Mode
    {
        return Mode::fromMixed($this->get('mode', 'detect'));
    }

    public function paranoiaLevel(): int
    {
        return (int) $this->get('paranoia_level', 1);
    }

    public function inboundThreshold(): int
    {
        return (int) $this->get('inbound_threshold', 5);
    }

    public function failClosed(): bool
    {
        return config('waf.fail_mode', 'open') === 'closed';
    }

    public function pepper(): string
    {
        $pepper = config('waf.pepper');

        return is_string($pepper) && $pepper !== '' ? $pepper : 'waf-insecure-default-pepper';
    }

    public function version(): int
    {
        return $this->settings->version();
    }

    /**
     * @return array<string, mixed>
     */
    public function all(): array
    {
        return $this->settings->all();
    }
}
