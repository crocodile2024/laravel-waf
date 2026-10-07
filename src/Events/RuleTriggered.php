<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Events;

use Crocodile2024\WAF\Engine\RequestContext;
use Crocodile2024\WAF\Engine\Rules\RuleMatch;
use Illuminate\Foundation\Events\Dispatchable;

final class RuleTriggered
{
    use Dispatchable;

    public function __construct(
        public readonly RequestContext $context,
        public readonly RuleMatch $match,
    ) {}
}
