<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Services;

use Crocodile2024\WAF\Support\IpMatcher;
use Illuminate\Support\Facades\Http;

/**
 * Ruft abonnierte Blocklisten ab und schreibt sie als Denylist-Einträge (Quelle „import“).
 * Ausschließlich per Scheduler-Job, nie im Request (5.6).
 */
class BlocklistUpdater
{
    public function __construct(
        private readonly ConfigManager $config,
        private readonly IpListService $lists,
    ) {}

    public function update(): int
    {
        $urls = (array) $this->config->get('blocklists.urls', []);
        $count = 0;
        foreach ($urls as $url) {
            $response = Http::timeout(60)->get((string) $url);
            if (! $response->successful()) {
                continue;
            }
            foreach (preg_split('/\r?\n/', $response->body()) ?: [] as $line) {
                $line = trim($line);
                if ($line === '' || str_starts_with($line, '#') || str_starts_with($line, ';')) {
                    continue;
                }
                $cidr = trim(explode(' ', $line)[0]);
                if (IpMatcher::isValidCidr($cidr)) {
                    try {
                        $this->lists->add('deny', $cidr, ['source' => 'import', 'comment' => 'Blockliste: '.$url]);
                        $count++;
                    } catch (\Throwable) {
                    }
                }
            }
        }

        return $count;
    }
}
