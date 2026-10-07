<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Engine\Rules;

use RuntimeException;

final class RuleValidationException extends RuntimeException
{
    /**
     * @param  array<int, string>  $errors
     */
    public function __construct(public readonly array $errors, public readonly ?string $ruleCode = null)
    {
        parent::__construct(($ruleCode !== null ? "Regel {$ruleCode}: " : '').implode(' ', $errors));
    }
}
