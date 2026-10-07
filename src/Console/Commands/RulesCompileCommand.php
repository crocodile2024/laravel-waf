<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Console\Commands;

use Crocodile2024\WAF\Services\RuleRegistry;
use Illuminate\Console\Command;

class RulesCompileCommand extends Command
{
    protected $signature = 'waf:rules:compile';

    protected $description = 'Kompiliert alle aktiven Regeln neu, legt den Plan in Redis ab und verteilt die Version.';

    public function handle(RuleRegistry $registry): int
    {
        $set = $registry->recompile();
        $this->info(sprintf('Regeln kompiliert (Version %d): %d Request-, %d Response-Regeln.',
            $set->version, count($set->request), count($set->response)));

        return self::SUCCESS;
    }
}
