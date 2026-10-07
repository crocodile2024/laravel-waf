<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Engine\Stages;

/**
 * Ergebnis einer Inspection-Stage.
 *
 * - continue: nächste Stage ausführen
 * - stop: Prüfung beenden (z. B. Allowlist), Request durchlassen
 * - act: Sofortaktion (block/challenge/ban/rate_limit) auslösen
 */
final class StageResult
{
    public const CONTINUE = 'continue';

    public const STOP = 'stop';

    public const ACT = 'act';

    /**
     * @param  array<int, \Crocodile2024\WAF\Engine\Rules\RuleMatch>  $matches
     */
    private function __construct(
        public readonly string $disposition,
        public readonly ?string $action = null,
        public readonly ?string $reason = null,
        public readonly array $matches = [],
        public readonly int $status = 403,
        public readonly int $score = 0,
        public readonly ?string $ruleCode = null,
        public readonly ?int $retryAfter = null,
    ) {}

    public static function next(int $score = 0): self
    {
        return new self(self::CONTINUE, score: $score);
    }

    public static function stop(?string $reason = null): self
    {
        return new self(self::STOP, reason: $reason);
    }

    /**
     * @param  array<int, \Crocodile2024\WAF\Engine\Rules\RuleMatch>  $matches
     */
    public static function act(
        string $action,
        string $reason,
        array $matches = [],
        int $status = 403,
        int $score = 0,
        ?string $ruleCode = null,
        ?int $retryAfter = null,
    ): self {
        return new self(self::ACT, $action, $reason, $matches, $status, $score, $ruleCode, $retryAfter);
    }
}
