<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Console\Commands;

use Crocodile2024\WAF\Services\IpListService;
use Illuminate\Console\Command;
use Illuminate\Support\Carbon;
use Throwable;

class AllowCommand extends Command
{
    protected $signature = 'waf:allow {ip} {--comment=} {--until=}';

    protected $description = 'Fügt eine IP/CIDR zur Allowlist hinzu.';

    public function handle(IpListService $lists): int
    {
        try {
            $lists->add('allow', (string) $this->argument('ip'), [
                'comment' => $this->option('comment'),
                'expires_at' => $this->option('until') ? Carbon::parse((string) $this->option('until')) : null,
                'source' => 'manual',
            ]);
            $this->info('Allowlist-Eintrag angelegt: '.$this->argument('ip'));

            return self::SUCCESS;
        } catch (Throwable $e) {
            $this->error($e->getMessage());

            return self::FAILURE;
        }
    }
}
