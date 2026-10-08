<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Services;

use Crocodile2024\WAF\Engine\Scoring\Severity;
use Crocodile2024\WAF\Models\NotificationChannel;
use Crocodile2024\WAF\Notifications\WafNotificationMail;
use Crocodile2024\WAF\Support\RedisStore;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Mail;
use Throwable;

/**
 * Benachrichtigungen über Mail- und Webhook-Kanäle mit Drosselung und Digest (13.).
 */
class NotificationService
{
    public function __construct(
        private readonly RedisStore $redis,
        private readonly ConfigManager $config,
    ) {}

    /**
     * @param  array<string, mixed>  $payload
     */
    public function notify(string $eventType, string $severity, array $payload): void
    {
        foreach (NotificationChannel::query()->where('is_active', true)->get() as $channel) {
            if (! in_array($eventType, (array) $channel->events, true)) {
                continue;
            }
            if (Severity::tryFrom($severity)?->rank() < Severity::tryFrom($channel->min_severity)?->rank()) {
                continue;
            }
            if ($channel->digest !== 'instant' || $this->throttled($channel->id, $eventType)) {
                $this->queueForDigest($channel->id, $eventType, $payload);

                continue;
            }
            $this->dispatch($channel, $eventType, $payload);
        }
    }

    public function sendDigest(string $period): int
    {
        $sent = 0;
        foreach (NotificationChannel::query()->where('is_active', true)->where('digest', $period)->get() as $channel) {
            $items = $this->redis->smembers('digest:'.$channel->id);
            if ($items === []) {
                continue;
            }
            $this->dispatch($channel, 'digest', ['period' => $period, 'items' => $items]);
            $this->redis->del('digest:'.$channel->id);
            $sent++;
        }

        return $sent;
    }

    private function throttled(string $channelId, string $eventType): bool
    {
        $key = 'notify:throttle:'.$channelId.':'.$eventType;
        if ($this->redis->exists($key)) {
            return true;
        }
        $this->redis->set($key, '1', (int) $this->config->get('notifications.throttle_minutes', 10) * 60);

        return false;
    }

    /**
     * @param  array<string, mixed>  $payload
     */
    private function queueForDigest(string $channelId, string $eventType, array $payload): void
    {
        $this->redis->sadd('digest:'.$channelId, $eventType.': '.json_encode($payload, JSON_UNESCAPED_UNICODE));
    }

    /**
     * @param  array<string, mixed>  $payload
     */
    private function dispatch(NotificationChannel $channel, string $eventType, array $payload): void
    {
        try {
            if ($channel->type === 'webhook') {
                $body = json_encode(['event' => $eventType, 'payload' => $payload, 'at' => now()->toIso8601String()], JSON_UNESCAPED_UNICODE) ?: '{}';
                $signature = hash_hmac('sha256', $body, (string) ($channel->secret ?? ''));
                Http::timeout(5)->withHeaders(['X-WAF-Signature' => 'sha256='.$signature, 'Content-Type' => 'application/json'])
                    ->withBody($body, 'application/json')->post($channel->target);
            } elseif ($channel->type === 'mail') {
                $mail = $eventType === 'digest'
                    ? new WafNotificationMail('digest', period: (string) ($payload['period'] ?? 'hourly'), items: array_map('strval', (array) ($payload['items'] ?? [])))
                    : new WafNotificationMail($eventType, payload: $payload);
                Mail::to($channel->target)->send($mail);
            }
        } catch (Throwable) {
            // Benachrichtigungen dürfen den Betrieb nicht stören.
        }
    }
}
