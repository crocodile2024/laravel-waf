<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Console\Commands;

use Crocodile2024\WAF\Services\GeoIpUpdater;
use Illuminate\Console\Command;
use Throwable;

class GeoIpUpdateCommand extends Command
{
    protected $signature = 'waf:geoip:update';

    protected $description = 'Lädt die GeoIP-Datenbanken mit dem hinterlegten Lizenzschlüssel herunter (einziger externer Aufruf).';

    public function handle(GeoIpUpdater $updater): int
    {
        try {
            $files = $updater->update();
            foreach ($files as $name => $ok) {
                $this->line(($ok ? '  ✓ ' : '  ✗ ').$name);
            }

            return self::SUCCESS;
        } catch (Throwable $e) {
            $this->error($e->getMessage());

            return self::FAILURE;
        }
    }
}
