<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Console\Commands;

use Crocodile2024\WAF\Services\RuleImporter;
use Crocodile2024\WAF\Services\RuleRegistry;
use Illuminate\Console\Command;
use Throwable;

class RulesImportCommand extends Command
{
    protected $signature = 'waf:rules:import {file? : Pfad zum Regelpaket (leer = mitgelieferte Kernregeln)}';

    protected $description = 'Importiert ein Regelpaket (JSON) oder aktualisiert die Kernregeln.';

    public function handle(RuleImporter $importer, RuleRegistry $registry): int
    {
        try {
            $file = $this->argument('file');
            $count = $file !== null ? $importer->importFile((string) $file) : $importer->importCorePack();
            $registry->recompile();
            $this->info("{$count} Regeln importiert.");

            return self::SUCCESS;
        } catch (Throwable $e) {
            $this->error($e->getMessage());

            return self::FAILURE;
        }
    }
}
