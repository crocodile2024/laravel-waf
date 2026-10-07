<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Engine;

use Crocodile2024\WAF\Engine\Rules\RuleMatcher;
use Crocodile2024\WAF\Engine\Scoring\ScoreBoard;
use Crocodile2024\WAF\Services\ExceptionService;

/**
 * Wertet eine RuleSet-Phase gegen einen RequestContext aus und liefert Treffer,
 * Score und die stärkste Sofortaktion. Ausnahmen werden vor der Score-Addition angewandt.
 */
final class Inspector
{
    public function __construct(
        private readonly ExceptionService $exceptions,
    ) {}

    /**
     * @param  array<int, array<string, mixed>>  $rules  kompilierte Regeln (bereits nach Priorität sortiert)
     */
    public function evaluate(
        RequestContext $ctx,
        array $rules,
        int $paranoiaLevel,
        Mode $mode,
        ?\Closure $tracer = null,
    ): InspectionResult {
        $matcher = new RuleMatcher($ctx, tracer: $tracer);
        $board = new ScoreBoard;
        $matches = [];
        $immediate = null;
        $tags = [];

        foreach ($rules as $rule) {
            if ($rule['pl'] > $paranoiaLevel) {
                continue;
            }
            $ruleMode = $rule['mode'] !== null ? Mode::fromMixed($rule['mode'], $mode) : $mode;
            if ($ruleMode === Mode::Off) {
                continue;
            }

            $hits = $matcher->match($rule, enforced: $ruleMode->enforces());
            if ($hits === []) {
                continue;
            }

            $kept = [];
            foreach ($hits as $hit) {
                if (! $this->exceptions->covers($ctx, $hit)) {
                    $kept[] = $hit;
                }
            }
            if ($kept === []) {
                continue;
            }

            foreach ($kept as $hit) {
                $matches[] = $hit;
            }
            $tags = [...$tags, ...$rule['tags']];

            $action = $rule['action'];
            $type = $action['type'] ?? 'score';

            if ($type === 'allow') {
                return new InspectionResult($matches, $board, new ImmediateAction('allow', $rule['code'], $kept[0], $ruleMode), $tags);
            }

            if ($type === 'score') {
                $board->add($rule['code'], $rule['points'] * count($kept));

                continue;
            }

            if ($type === 'tag') {
                $tags[] = (string) ($action['tag'] ?? $rule['code']);

                continue;
            }

            if ($type === 'log') {
                continue;
            }

            // block | challenge | ban | rate_limit: stärkste/erste Sofortaktion merken
            $candidate = new ImmediateAction($type, $rule['code'], $kept[0], $ruleMode, $action);
            if ($immediate === null || $candidate->rank() > $immediate->rank()) {
                $immediate = $candidate;
            }
            // Punkte zusätzlich zählen (Schwere der Regel)
            $board->add($rule['code'], $rule['points'] * count($kept));
        }

        return new InspectionResult($matches, $board, $immediate, array_values(array_unique($tags)));
    }
}
