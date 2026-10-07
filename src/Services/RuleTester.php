<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Services;

use Crocodile2024\WAF\Engine\Mode;
use Crocodile2024\WAF\Engine\Normalizer\Transformer;
use Crocodile2024\WAF\Engine\RequestContext;
use Crocodile2024\WAF\Engine\Rules\RuleMatcher;
use Crocodile2024\WAF\Engine\Scoring\ScoreBoard;

/**
 * Regel-Tester (5.4): wertet einen Beispiel-Request gegen alle Regeln aus und
 * liefert Treffer, Score, Ergebnis und Normalisierungsschritte.
 */
class RuleTester
{
    public function __construct(
        private readonly RuleRegistry $rules,
        private readonly ConfigManager $config,
    ) {}

    /**
     * Baut einen RequestContext aus Roh-Request-Bestandteilen.
     *
     * @return array{result: string, score: int, threshold: int, matches: array<int, array<string, mixed>>, normalizations: array<int, array<string, mixed>>}
     */
    public function test(string $method, string $path, string $rawBody = '', array $headers = [], ?int $paranoia = null): array
    {
        $query = [];
        $parsedPath = $path;
        if (str_contains($path, '?')) {
            [$parsedPath, $qs] = explode('?', $path, 2);
            parse_str($qs, $query);
        }
        $body = [];
        $contentType = strtolower((string) ($headers['content-type'] ?? $headers['Content-Type'] ?? ''));
        if ($rawBody !== '') {
            if (str_contains($contentType, 'json')) {
                $decoded = json_decode($rawBody, true);
                $body = is_array($decoded) ? $decoded : ['_raw' => $rawBody];
            } else {
                parse_str($rawBody, $body);
            }
        }

        $ctx = RequestContext::make([
            'method' => $method,
            'path' => $parsedPath,
            'uri' => $path,
            'query' => $query,
            'body' => $body,
            'raw_body' => $rawBody,
            'headers' => $headers,
        ]);

        $paranoia ??= $this->config->paranoiaLevel();
        $plan = $this->rules->current();

        $normalizations = [];
        $matcher = new RuleMatcher($ctx, tracer: function (string $target, ?string $param, string $raw, string $normalized, array $transforms) use (&$normalizations): void {
            if ($raw !== $normalized) {
                $normalizations[] = [
                    'target' => $target,
                    'parameter' => $param,
                    'transforms' => $transforms,
                    'steps' => Transformer::trace($raw, $transforms),
                ];
            }
        });

        $board = new ScoreBoard;
        $matches = [];
        foreach ($plan->request as $rule) {
            if ($rule['pl'] > $paranoia) {
                continue;
            }
            foreach ($matcher->match($rule) as $hit) {
                $matches[] = [
                    'rule_code' => $hit->ruleCode,
                    'rule_name' => $hit->ruleName,
                    'severity' => $hit->severity,
                    'target' => $hit->target,
                    'parameter' => $hit->parameter,
                    'action' => $rule['action']['type'] ?? 'score',
                    'points' => $rule['points'],
                ];
                $type = $rule['action']['type'] ?? 'score';
                if (in_array($type, ['score', 'block', 'ban', 'challenge'], true)) {
                    $board->add($hit->ruleCode, $rule['points']);
                }
            }
        }

        $threshold = $this->config->inboundThreshold();
        $hasBlock = collect($matches)->contains(fn ($m) => in_array($m['action'], ['block', 'ban'], true));
        $result = ($hasBlock || $board->total() >= $threshold) ? 'blockiert' : ($matches !== [] ? 'protokolliert' : 'durchgelassen');

        return [
            'result' => $result,
            'score' => $board->total(),
            'threshold' => $threshold,
            'matches' => $matches,
            'normalizations' => $normalizations,
        ];
    }
}
