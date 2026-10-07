<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Engine\Rules;

/**
 * Ein einzelner Regeltreffer.
 */
final class RuleMatch
{
    /**
     * @param  array<int, string>  $tags
     * @param  array<int, string>  $transforms
     */
    public function __construct(
        public readonly string $ruleCode,
        public readonly string $ruleName,
        public readonly string $severity,
        public readonly int $points,
        public readonly string $target,
        public readonly ?string $parameter,
        public readonly string $value,
        public readonly ?int $offset,
        public readonly array $tags = [],
        public readonly array $transforms = [],
        public readonly bool $enforced = true,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'rule_code' => $this->ruleCode,
            'rule_name' => $this->ruleName,
            'severity' => $this->severity,
            'points' => $this->points,
            'target' => $this->target,
            'parameter' => $this->parameter,
            'transforms' => $this->transforms,
            'enforced' => $this->enforced,
        ];
    }
}
