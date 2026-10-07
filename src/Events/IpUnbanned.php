<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Events;

use Illuminate\Foundation\Events\Dispatchable;

final class IpUnbanned
{
    use Dispatchable;

    public function __construct(
        public readonly string $ipKey,
        public readonly ?string $by = null,
    ) {}
}
