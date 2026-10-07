<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Events;

use Illuminate\Foundation\Events\Dispatchable;

final class ConfigChanged
{
    use Dispatchable;

    public function __construct(
        public readonly string $key,
        public readonly mixed $oldValue = null,
        public readonly mixed $newValue = null,
        public readonly ?string $by = null,
    ) {}
}
