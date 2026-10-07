<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Engine;

use Crocodile2024\WAF\Engine\Rules\RuleMatch;

/**
 * Ergebnis der Firewall-Prüfung eines Requests.
 */
final class Decision
{
    public const ALLOW = 'allow';      // durchlassen (ohne Treffer)

    public const PASS = 'pass';        // Treffer, aber nicht durchgesetzt (detect/learning) oder unter Schwelle

    public const BLOCK = 'block';

    public const CHALLENGE = 'challenge';

    public const RATE_LIMIT = 'rate_limit';

    /**
     * @param  array<int, RuleMatch>  $matches
     */
    public function __construct(
        public readonly string $type,
        public readonly RequestContext $context,
        public readonly string $outcome,
        public readonly int $status = 200,
        public readonly int $score = 0,
        public readonly array $matches = [],
        public readonly ?string $ruleCode = null,
        public readonly ?int $retryAfter = null,
        public readonly bool $enforced = true,
    ) {}

    public function shouldBlock(): bool
    {
        return $this->enforced && in_array($this->type, [self::BLOCK, self::CHALLENGE, self::RATE_LIMIT], true);
    }

    public function incidentId(): string
    {
        return $this->context->id;
    }
}
