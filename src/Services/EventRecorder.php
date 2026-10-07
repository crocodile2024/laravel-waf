<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Services;

use Crocodile2024\WAF\Engine\RequestContext;
use Crocodile2024\WAF\Engine\Rules\RuleMatch;
use Crocodile2024\WAF\Support\Anonymizer;
use Crocodile2024\WAF\Support\RedisStore;
use Crocodile2024\WAF\Support\Redactor;

/**
 * Schreibt Ereignisse nicht-blockierend in eine Redis-Warteschlange (6.).
 * Saubere Requests werden nur gezählt (INCR). Payloads werden geschwärzt & gekürzt.
 */
class EventRecorder
{
    public function __construct(
        private readonly RedisStore $redis,
        private readonly ConfigManager $config,
        private readonly Redactor $redactor,
    ) {}

    /**
     * @param  array<int, RuleMatch>  $matches
     */
    public function record(
        RequestContext $ctx,
        string $outcome,
        string $mode,
        ?int $statusCode,
        int $score,
        array $matches,
    ): void {
        $payload = [
            'id' => $ctx->id,
            'occurred_at' => now()->format('Y-m-d H:i:s.v'),
            'ip' => $ctx->ip,
            'ip_hash' => Anonymizer::hash($ctx->ip, $this->config->pepper()),
            'country' => $ctx->attributes->country,
            'asn' => $ctx->attributes->asn,
            'method' => $ctx->method,
            'host' => mb_substr($ctx->host, 0, 255),
            'path' => mb_substr($ctx->path, 0, 2048),
            'route_name' => $ctx->routeName(),
            'user_agent' => mb_substr($ctx->userAgent, 0, 512),
            'user_id' => $this->config->get('privacy.store_user_id', false) ? (string) ($ctx->userId() ?? '') : null,
            'mode' => $mode,
            'outcome' => $outcome,
            'status_code' => $statusCode,
            'score' => $score,
            'matches' => $this->serializeMatches($ctx, $matches),
            'node' => $this->nodeName(),
        ];

        $maxLen = (int) $this->config->get('events.max_queue_length', 100000);
        if ($this->redis->llen('events:queue') < $maxLen) {
            $this->redis->rpush('events:queue', (string) json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
        }
    }

    public function countClean(): void
    {
        $this->redis->incr('counter:'.now()->format('YmdH'), 1, 90000);
    }

    /**
     * @param  array<int, RuleMatch>  $matches
     * @return array<int, array<string, mixed>>
     */
    private function serializeMatches(RequestContext $ctx, array $matches): array
    {
        $out = [];
        foreach ($matches as $match) {
            $out[] = [
                'rule_code' => $match->ruleCode,
                'rule_name' => $match->ruleName,
                'severity' => $match->severity,
                'target' => $match->target,
                'parameter' => $match->parameter,
                'transforms' => $match->transforms,
                'snippet' => $this->redactor->snippet($match->parameter, $match->value, $match->offset),
            ];
        }

        return $out;
    }

    private function nodeName(): string
    {
        $name = $this->config->get('cluster.node_name');

        return is_string($name) && $name !== '' ? $name : (gethostname() ?: 'unknown');
    }
}
