<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Console\Commands;

use Crocodile2024\WAF\Models\Rule;
use Illuminate\Console\Command;

class RulesExportCommand extends Command
{
    protected $signature = 'waf:rules:export {file : Zieldatei}';

    protected $description = 'Exportiert die eigenen Regeln als Regelpaket (JSON).';

    public function handle(): int
    {
        $rules = Rule::query()->where('source', 'custom')->orderBy('priority')->get()
            ->map(fn (Rule $r) => $r->toDefinition())->all();
        $pack = [
            'schema' => 'waf-rulepack/1',
            'pack' => 'custom-export',
            'version' => now()->format('Y.m.d'),
            'rules' => $rules,
        ];
        file_put_contents((string) $this->argument('file'), (string) json_encode($pack, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
        $this->info(count($rules).' eigene Regeln exportiert nach '.$this->argument('file'));

        return self::SUCCESS;
    }
}
