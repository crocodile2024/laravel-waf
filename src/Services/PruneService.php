<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Services;

use Crocodile2024\WAF\Models\Ban;
use Crocodile2024\WAF\Models\CspReport;
use Crocodile2024\WAF\Models\Event;
use Crocodile2024\WAF\Models\IpEntry;
use Crocodile2024\WAF\Models\StatHourly;
use Crocodile2024\WAF\Models\WafException;
use Crocodile2024\WAF\Support\Anonymizer;

/**
 * Anonymisierung und Altdatenlöschung (7.).
 */
class PruneService
{
    public function __construct(
        private readonly ConfigManager $config,
    ) {}

    /**
     * @return array{anonymized: int, deleted_events: int, deleted_stats: int, expired: int}
     */
    public function run(): array
    {
        return [
            'anonymized' => $this->anonymize(),
            'deleted_events' => $this->deleteOldEvents(),
            'deleted_stats' => $this->deleteOldStats(),
            'expired' => $this->removeExpired(),
        ];
    }

    private function anonymize(): int
    {
        $days = (int) $this->config->get('privacy.anonymize_after_days', 7);
        $cutoff = now()->subDays($days);
        $count = 0;

        Event::query()->whereNull('anonymized_at')->where('occurred_at', '<', $cutoff)
            ->whereNotNull('ip')->chunkById(500, function ($events) use (&$count): void {
                foreach ($events as $event) {
                    $event->forceFill([
                        'ip' => $event->ip !== null ? Anonymizer::anonymize($event->ip) : null,
                        'user_agent' => null,
                        'anonymized_at' => now(),
                    ])->saveQuietly();
                    $count++;
                }
            });

        return $count;
    }

    private function deleteOldEvents(): int
    {
        $days = (int) $this->config->get('privacy.retention_days', 30);

        return Event::query()->where('occurred_at', '<', now()->subDays($days))->delete();
    }

    private function deleteOldStats(): int
    {
        $days = (int) $this->config->get('privacy.stats_retention_days', 400);

        return StatHourly::query()->where('hour', '<', now()->subDays($days))->delete();
    }

    private function removeExpired(): int
    {
        $count = 0;
        $count += Ban::query()->whereNotNull('banned_until')->where('banned_until', '<', now())->whereNull('lifted_at')->update(['lifted_at' => now()]);
        $count += IpEntry::query()->whereNotNull('expires_at')->where('expires_at', '<', now())->delete();
        $count += WafException::query()->whereNotNull('expires_at')->where('expires_at', '<', now())->delete();
        CspReport::query()->where('received_at', '<', now()->subDays(90))->delete();

        return $count;
    }
}
