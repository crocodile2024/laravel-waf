<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Console\Commands;

use Crocodile2024\WAF\Services\BlocklistUpdater;
use Illuminate\Console\Command;

class BlocklistsUpdateCommand extends Command
{
    protected $signature = 'waf:blocklists:update';

    protected $description = 'Ruft abonnierte Blocklisten ab (nur per Scheduler, nie im Request).';

    public function handle(BlocklistUpdater $updater): int
    {
        if (! config('waf.blocklists.enabled', false)) {
            $this->warn('Abonnierte Blocklisten sind deaktiviert.');

            return self::SUCCESS;
        }
        $count = $updater->update();
        $this->info("{$count} Einträge aus Blocklisten aktualisiert.");

        return self::SUCCESS;
    }
}
