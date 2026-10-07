<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Console\Commands;

use Crocodile2024\WAF\Services\BanService;
use Crocodile2024\WAF\Services\IpListService;
use Illuminate\Console\Command;

class SyncCommand extends Command
{
    protected $signature = 'waf:sync';

    protected $description = 'Lädt aktive Bans und IP-Listen aus der DB zurück nach Redis.';

    public function handle(BanService $bans, IpListService $lists): int
    {
        $count = $bans->syncFromDatabase();
        $lists->rebuildAll();
        $this->info("{$count} Bans und die IP-Listen wurden nach Redis geladen.");

        return self::SUCCESS;
    }
}
