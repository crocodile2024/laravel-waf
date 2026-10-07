<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Console\Commands;

use Crocodile2024\WAF\Services\PruneService;
use Illuminate\Console\Command;

class PruneCommand extends Command
{
    protected $signature = 'waf:prune';

    protected $description = 'Anonymisiert und löscht Altdaten gemäß Datenschutz-Einstellungen.';

    public function handle(PruneService $prune): int
    {
        $result = $prune->run();
        $this->info(sprintf('Anonymisiert: %d, gelöschte Ereignisse: %d, gelöschte Statistiken: %d, abgelaufen: %d.',
            $result['anonymized'], $result['deleted_events'], $result['deleted_stats'], $result['expired']));

        return self::SUCCESS;
    }
}
