<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Events;

use Crocodile2024\WAF\Engine\RequestContext;
use Illuminate\Foundation\Events\Dispatchable;

final class RequestBlocked
{
    use Dispatchable;

    /**
     * @param  array<int, array<string, mixed>>  $matches
     */
    public function __construct(
        public readonly RequestContext $context,
        public readonly array $matches = [],
        public readonly int $score = 0,
        public readonly ?int $status = null,
    ) {}
}
