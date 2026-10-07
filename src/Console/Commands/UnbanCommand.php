<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Console\Commands;

use Crocodile2024\WAF\Services\BanService;
use Illuminate\Console\Command;

class UnbanCommand extends Command
{
    protected $signature = 'waf:unban {ip}';

    protected $description = 'Hebt die Sperre einer IP-Adresse auf.';

    public function handle(BanService $bans): int
    {
        $bans->unban((string) $this->argument('ip'), 'CLI');
        $this->info('Sperre aufgehoben: '.$this->argument('ip'));

        return self::SUCCESS;
    }
}
