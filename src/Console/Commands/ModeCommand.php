<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Console\Commands;

use Crocodile2024\WAF\Engine\Mode;
use Crocodile2024\WAF\Services\AuditLogger;
use Crocodile2024\WAF\Services\SettingsRepository;
use Illuminate\Console\Command;

class ModeCommand extends Command
{
    protected $signature = 'waf:mode {mode : off|learning|detect|block}';

    protected $description = 'Setzt den WAF-Modus (mit Audit-Eintrag „CLI“).';

    public function handle(SettingsRepository $settings, AuditLogger $audit): int
    {
        $mode = Mode::tryFrom((string) $this->argument('mode'));
        if ($mode === null) {
            $this->error('Ungültiger Modus. Erlaubt: '.implode(', ', Mode::values()));

            return self::FAILURE;
        }
        $old = $settings->get('mode');
        $settings->set('mode', $mode->value, 'CLI');
        $audit->log('mode.change', 'config', 'mode', ['from' => $old, 'to' => $mode->value], 'CLI');
        $this->info('Modus gesetzt: '.$mode->label());

        return self::SUCCESS;
    }
}
