<?php

declare(strict_types=1);

use Crocodile2024\WAF\Engine\Mode;
use Crocodile2024\WAF\Engine\RequestContext;
use Crocodile2024\WAF\Engine\Rules\RuleCompiler;
use Crocodile2024\WAF\Engine\Rules\RuleMatcher;
use Crocodile2024\WAF\Engine\Scoring\ScoreBoard;

/**
 * @return array<int, array<string, mixed>>
 */
function compiledCoreRules(): array
{
    static $rules = null;
    if ($rules !== null) {
        return $rules;
    }
    $pack = json_decode((string) file_get_contents(__DIR__.'/../../resources/rules/core-v1.json'), true);
    $compiler = new RuleCompiler;
    $rules = array_map(static fn (array $r) => $compiler->compile($r), $pack['rules']);
    usort($rules, static fn (array $a, array $b) => $a['priority'] <=> $b['priority']);

    return $rules;
}

/**
 * Wertet einen einzelnen Wert gegen alle Request-Regeln bis Paranoia-Level aus.
 *
 * @return array{score: int, codes: array<int, string>}
 */
function inspectValue(string $payload, int $paranoia, string $target = 'q'): array
{
    $ctx = RequestContext::make([
        'method' => 'POST',
        'path' => '/suche',
        'query' => [$target => $payload],
        'body' => [$target => $payload],
        'raw_body' => $payload,
        'headers' => ['user-agent' => 'Mozilla/5.0', 'content-type' => 'application/x-www-form-urlencoded'],
    ]);
    $matcher = new RuleMatcher($ctx);
    $board = new ScoreBoard;
    $codes = [];
    foreach (compiledCoreRules() as $rule) {
        if ($rule['pl'] > $paranoia || $rule['phase'] !== 'request') {
            continue;
        }
        $hits = $matcher->match($rule);
        if ($hits !== []) {
            $codes[] = $rule['code'];
            $type = $rule['action']['type'] ?? 'score';
            if (in_array($type, ['score', 'block', 'ban', 'challenge'], true)) {
                $board->add($rule['code'], $rule['points']);
            }
        }
    }

    return ['score' => $board->total(), 'codes' => array_values(array_unique($codes))];
}

/**
 * @return array<int, string>
 */
function readCorpus(string $file): array
{
    $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];

    return array_values(array_filter($lines, static fn (string $l) => ! str_starts_with(ltrim($l), '#')));
}

$attackFiles = glob(__DIR__.'/../Fixtures/attacks/*.txt') ?: [];
$benignFiles = glob(__DIR__.'/../Fixtures/benign/*.txt') ?: [];

test('attack corpus is detected at paranoia 1 (>= 95%)', function () use ($attackFiles) {
    expect($attackFiles)->not->toBeEmpty();
    $total = 0;
    $detected = 0;
    $missed = [];
    foreach ($attackFiles as $file) {
        foreach (readCorpus($file) as $payload) {
            $total++;
            $result = inspectValue($payload, 1);
            if ($result['score'] >= 5 || $result['codes'] !== []) {
                $detected++;
            } else {
                $missed[] = basename($file).': '.$payload;
            }
        }
    }
    $rate = $detected / max(1, $total);
    expect($rate)->toBeGreaterThanOrEqual(0.95, sprintf(
        "Erkennungsrate %.1f%% (%d/%d). Verpasst:\n%s",
        $rate * 100, $detected, $total, implode("\n", array_slice($missed, 0, 30)),
    ));
});

test('attack corpus is detected at paranoia 2 (>= 99%)', function () use ($attackFiles) {
    $total = 0;
    $detected = 0;
    $missed = [];
    foreach ($attackFiles as $file) {
        foreach (readCorpus($file) as $payload) {
            $total++;
            $result = inspectValue($payload, 2);
            if ($result['codes'] !== []) {
                $detected++;
            } else {
                $missed[] = basename($file).': '.$payload;
            }
        }
    }
    $rate = $detected / max(1, $total);
    expect($rate)->toBeGreaterThanOrEqual(0.99, sprintf(
        "Erkennungsrate %.1f%% (%d/%d). Verpasst:\n%s",
        $rate * 100, $detected, $total, implode("\n", $missed),
    ));
});

test('benign corpus produces zero hits at paranoia 1', function () use ($benignFiles) {
    expect($benignFiles)->not->toBeEmpty();
    $falsePositives = [];
    foreach ($benignFiles as $file) {
        foreach (readCorpus($file) as $payload) {
            foreach (['q', 'name', 'kommentar', 'email', 'nachricht'] as $field) {
                $result = inspectValue($payload, 1, $field);
                if ($result['codes'] !== []) {
                    $falsePositives[] = basename($file).' ['.$field.']: '.$payload.' → '.implode(',', $result['codes']);
                    break;
                }
            }
        }
    }
    expect($falsePositives)->toBe([], "Fehlalarme bei Paranoia 1:\n".implode("\n", $falsePositives));
});
