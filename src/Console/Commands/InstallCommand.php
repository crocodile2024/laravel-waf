<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Console\Commands;

use Crocodile2024\WAF\Services\RuleImporter;
use Illuminate\Console\Command;
use Illuminate\Support\Str;

class InstallCommand extends Command
{
    protected $signature = 'waf:install {--force : Vorhandene Dateien überschreiben}';

    protected $description = 'Publiziert Config, Assets und Migrationen, migriert, erzeugt den Pepper und importiert die Kernregeln.';

    public function handle(RuleImporter $importer): int
    {
        $this->info('WAF-Installation startet …');

        $this->call('vendor:publish', ['--tag' => 'waf-config', '--force' => (bool) $this->option('force')]);
        $this->call('vendor:publish', ['--tag' => 'waf-migrations', '--force' => (bool) $this->option('force')]);
        $this->call('vendor:publish', ['--tag' => 'waf-assets', '--force' => true]);

        $this->ensurePepper();

        $this->info('Migrationen werden ausgeführt …');
        $this->call('migrate');

        $this->info('Kernregeln werden importiert …');
        $count = $importer->importCorePack();
        $this->line("  {$count} Regeln importiert/aktualisiert.");

        $this->call('waf:rules:compile');

        $this->newLine();
        $this->warn('Wichtig: Definieren Sie das Gate „'.config('waf.ui.gate', 'viewWAF').'“ in Ihrem AppServiceProvider:');
        $this->line(<<<'PHP'

    use Illuminate\Support\Facades\Gate;

    Gate::define('viewWAF', function ($user) {
        return $user->isAdmin(); // an Ihre Logik anpassen
    });

PHP);

        $this->checkTrustProxies();

        $this->newLine();
        $this->info('WAF installiert. UI erreichbar unter: /'.ltrim((string) config('waf.ui.path', 'admin/waf'), '/'));

        return self::SUCCESS;
    }

    private function ensurePepper(): void
    {
        $envPath = base_path('.env');
        if (! is_file($envPath)) {
            return;
        }
        $env = (string) file_get_contents($envPath);
        if (str_contains($env, 'WAF_PEPPER=') && (string) config('waf.pepper') !== '') {
            return;
        }
        $pepper = Str::random(64);
        if (str_contains($env, 'WAF_PEPPER=')) {
            $env = (string) preg_replace('/WAF_PEPPER=.*/', 'WAF_PEPPER='.$pepper, $env);
        } else {
            $env .= PHP_EOL.'WAF_PEPPER='.$pepper.PHP_EOL;
        }
        file_put_contents($envPath, $env);
        $this->line('  WAF_PEPPER erzeugt und in .env geschrieben.');
    }

    private function checkTrustProxies(): void
    {
        $this->newLine();
        $this->warn('Prüfen Sie Ihre TrustProxies-Konfiguration – ohne korrekte Client-IP ist die WAF wirkungslos.');
        $this->line('  Beispiele für Hetzner Load Balancer und ISPConfig/nginx finden Sie in der README.');
    }
}
