<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Engine;

use Crocodile2024\WAF\Engine\Rules\RuleMatch;
use Crocodile2024\WAF\Engine\Scoring\ScoreBoard;

final class InspectionResult
{
    /**
     * @param  array<int, RuleMatch>  $matches
     * @param  array<int, string>  $tags
     */
    public function __construct(
        public readonly array $matches,
        public readonly ScoreBoard $score,
        public readonly ?ImmediateAction $immediate,
        public readonly array $tags = [],
    ) {}

    public function hasHits(): bool
    {
        return $this->matches !== [];
    }

    public function isAllow(): bool
    {
        return $this->immediate?->type === 'allow';
    }
}
