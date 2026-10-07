<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Events;

use Illuminate\Foundation\Events\Dispatchable;

final class IpBanned
{
    use Dispatchable;

    public function __construct(
        public readonly string $ipKey,
        public readonly int $until,
        public readonly string $reason,
        public readonly string $source,
    ) {}
}
