<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Console\Commands;

use Crocodile2024\WAF\Services\NotificationService;
use Illuminate\Console\Command;

class NotifyDigestCommand extends Command
{
    protected $signature = 'waf:notify:digest {period : hourly|daily}';

    protected $description = 'Versendet Digest-Benachrichtigungen.';

    public function handle(NotificationService $notifications): int
    {
        $period = (string) $this->argument('period');
        if (! in_array($period, ['hourly', 'daily'], true)) {
            $this->error('Zeitraum muss „hourly“ oder „daily“ sein.');

            return self::FAILURE;
        }
        $sent = $notifications->sendDigest($period);
        $this->info("{$sent} Digest-Benachrichtigungen versendet.");

        return self::SUCCESS;
    }
}
