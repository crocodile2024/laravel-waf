<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Console\Commands;

use Crocodile2024\WAF\Services\BanService;
use Crocodile2024\WAF\Support\IpMatcher;
use Illuminate\Console\Command;

class BanCommand extends Command
{
    protected $signature = 'waf:ban {ip} {--minutes=} {--reason=manuell (CLI)}';

    protected $description = 'Sperrt eine IP-Adresse.';

    public function handle(BanService $bans): int
    {
        $ip = (string) $this->argument('ip');
        if (! IpMatcher::isValidIp($ip)) {
            $this->error('Ungültige IP-Adresse.');

            return self::FAILURE;
        }
        $minutes = $this->option('minutes') !== null ? (int) $this->option('minutes') : null;
        $ban = $bans->ban($ip, $minutes, (string) $this->option('reason'), 'manual');
        $this->info("IP {$ip} gesperrt bis ".($ban->banned_until?->format('d.m.Y H:i') ?? 'unbegrenzt').'.');

        return self::SUCCESS;
    }
}
