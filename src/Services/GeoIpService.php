<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Services;

use GeoIp2\Database\Reader;
use Throwable;

/**
 * Lokale MaxMind-/DB-IP-Abfrage (5.7). Keine Online-Abfrage zur Laufzeit.
 */
class GeoIpService
{
    private ?Reader $countryReader = null;

    private ?Reader $asnReader = null;

    private bool $countryTried = false;

    private bool $asnTried = false;

    public function __construct(
        private readonly ConfigManager $config,
    ) {}

    public function available(): bool
    {
        return $this->countryDbPath() !== null || $this->asnDbPath() !== null;
    }

    public function countryDbPath(): ?string
    {
        $path = (string) $this->config->get('geoip.country_db', '');

        return $path !== '' && is_file($path) ? $path : null;
    }

    public function asnDbPath(): ?string
    {
        $path = (string) $this->config->get('geoip.asn_db', '');

        return $path !== '' && is_file($path) ? $path : null;
    }

    public function country(string $ip): ?string
    {
        if (! $this->countryTried) {
            $this->countryTried = true;
            $path = $this->countryDbPath();
            if ($path !== null && class_exists(Reader::class)) {
                try {
                    $this->countryReader = new Reader($path);
                } catch (Throwable) {
                    $this->countryReader = null;
                }
            }
        }
        if ($this->countryReader === null) {
            return null;
        }
        try {
            return $this->countryReader->country($ip)->country->isoCode;
        } catch (Throwable) {
            return null;
        }
    }

    public function asn(string $ip): ?int
    {
        if (! $this->asnTried) {
            $this->asnTried = true;
            $path = $this->asnDbPath();
            if ($path !== null && class_exists(Reader::class)) {
                try {
                    $this->asnReader = new Reader($path);
                } catch (Throwable) {
                    $this->asnReader = null;
                }
            }
        }
        if ($this->asnReader === null) {
            return null;
        }
        try {
            return $this->asnReader->asn($ip)->autonomousSystemNumber;
        } catch (Throwable) {
            return null;
        }
    }

    public function databaseAgeDays(): ?int
    {
        $path = $this->countryDbPath();
        if ($path === null) {
            return null;
        }
        $mtime = @filemtime($path);

        return $mtime === false ? null : (int) floor((time() - $mtime) / 86400);
    }
}
