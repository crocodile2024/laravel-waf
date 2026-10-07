<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Services;

use Crocodile2024\WAF\Models\AuditLog;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Request;

/**
 * Schreibt unveränderliche Audit-Einträge (10.1).
 */
class AuditLogger
{
    /**
     * @param  array<string, mixed>|null  $changes
     */
    public function log(string $action, ?string $subjectType = null, ?string $subjectId = null, ?array $changes = null, ?string $actor = null): void
    {
        AuditLog::query()->create([
            'user_id' => $actor ?? (string) (Auth::id() ?? 'system'),
            'action' => $action,
            'subject_type' => $subjectType,
            'subject_id' => $subjectId,
            'changes' => $changes,
            'ip' => Request::ip(),
            'created_at' => now(),
        ]);
    }
}
