<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Services;

final class RateLimitResult
{
    public function __construct(
        public readonly bool $allowed,
        public readonly int $limit,
        public readonly int $remaining,
        public readonly int $retryAfter,
        public readonly int $window,
    ) {}

    public function exceeded(): bool
    {
        return ! $this->allowed;
    }

    public function reset(): int
    {
        return time() + ($this->retryAfter > 0 ? $this->retryAfter : $this->window);
    }
}
