<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Console\Commands;

use Crocodile2024\WAF\Services\EventFlusher;
use Illuminate\Console\Command;

class EventsFlushCommand extends Command
{
    protected $signature = 'waf:events:flush';

    protected $description = 'Schreibt die Ereignis-Warteschlange in die DB und aggregiert Statistiken.';

    public function handle(EventFlusher $flusher): int
    {
        $count = $flusher->flush();
        $this->info("{$count} Ereignisse geschrieben.");

        return self::SUCCESS;
    }
}
