<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Engine;

use Crocodile2024\WAF\Engine\Rules\RuleMatch;

/**
 * Eine von einer Regel ausgelöste Sofortaktion.
 */
final class ImmediateAction
{
    /**
     * @param  array<string, mixed>  $params
     */
    public function __construct(
        public readonly string $type,
        public readonly string $ruleCode,
        public readonly RuleMatch $match,
        public readonly Mode $mode,
        public readonly array $params = [],
    ) {}

    public function rank(): int
    {
        return match ($this->type) {
            'allow' => 100,
            'ban' => 90,
            'block' => 80,
            'challenge' => 70,
            'rate_limit' => 60,
            default => 0,
        };
    }

    public function status(): int
    {
        return (int) ($this->params['status'] ?? 403);
    }

    public function banMinutes(): ?int
    {
        return isset($this->params['minutes']) ? (int) $this->params['minutes'] : null;
    }

    public function profile(): ?string
    {
        return isset($this->params['profile']) ? (string) $this->params['profile'] : null;
    }

    public function enforced(): bool
    {
        return $this->mode->enforces();
    }
}
