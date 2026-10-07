<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Console\Commands;

use Crocodile2024\WAF\Services\RuleTester;
use Illuminate\Console\Command;

class RulesTestCommand extends Command
{
    protected $signature = 'waf:rules:test {--payload= : Payload als Query-String oder Body}
        {--method=GET} {--path=/} {--file= : Datei mit Roh-Request-Body} {--paranoia=}';

    protected $description = 'Testet einen Beispiel-Request gegen die Regeln.';

    public function handle(RuleTester $tester): int
    {
        $body = '';
        if ($this->option('file') !== null) {
            $body = (string) file_get_contents((string) $this->option('file'));
        } elseif ($this->option('payload') !== null) {
            $body = (string) $this->option('payload');
        } elseif (! $this->input->isInteractive()) {
            $body = (string) $this->option('payload');
        } else {
            $body = (string) $this->ask('Payload (Body/Query)');
        }

        $path = (string) $this->option('path');
        $method = strtoupper((string) $this->option('method'));
        if ($method === 'GET' && $body !== '' && ! str_contains($path, '?')) {
            $path .= '?'.$body;
            $body = '';
        }

        $paranoia = $this->option('paranoia') !== null ? (int) $this->option('paranoia') : null;
        $result = $tester->test($method, $path, $body, ['content-type' => 'application/x-www-form-urlencoded'], $paranoia);

        $this->line('Ergebnis:   <options=bold>'.$result['result'].'</>');
        $this->line('Score:      '.$result['score'].' / '.$result['threshold']);
        if ($result['matches'] === []) {
            $this->info('Keine Treffer.');
        } else {
            $this->table(['Regel', 'Name', 'Ziel', 'Parameter', 'Aktion', 'Punkte'],
                array_map(fn ($m) => [$m['rule_code'], $m['rule_name'], $m['target'], $m['parameter'] ?? '-', $m['action'], $m['points']], $result['matches']));
        }

        return self::SUCCESS;
    }
}
