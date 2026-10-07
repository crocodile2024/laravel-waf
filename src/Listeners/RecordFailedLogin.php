<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Listeners;

use Crocodile2024\WAF\Services\LoginGuard;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Http\Request;

/**
 * Verbindet Laravels Auth-Events mit dem Login-Bruteforce-Schutz.
 */
class RecordFailedLogin
{
    public function __construct(
        private readonly LoginGuard $guard,
        private readonly Request $request,
    ) {}

    public function handleFailed(Failed $event): void
    {
        $identifier = null;
        foreach (['email', 'username', 'name', 'login'] as $field) {
            if (isset($event->credentials[$field]) && is_scalar($event->credentials[$field])) {
                $identifier = (string) $event->credentials[$field];
                break;
            }
        }

        $this->guard->recordFailure((string) ($this->request->ip() ?? '0.0.0.0'), $identifier);
    }

    public function handleLockout(Lockout $event): void
    {
        $this->guard->recordFailure((string) ($this->request->ip() ?? '0.0.0.0'), null);
    }
}
