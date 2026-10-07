<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use LogicException;

/**
 * Unveränderlicher Audit-Log-Eintrag (kein Update/Delete über das Model).
 */
class AuditLog extends Model
{
    use HasUlids;

    protected $table = 'waf_audit_log';

    public const UPDATED_AT = null;

    protected $fillable = ['user_id', 'action', 'subject_type', 'subject_id', 'changes', 'ip'];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return ['changes' => 'array', 'created_at' => 'datetime'];
    }

    protected static function booted(): void
    {
        static::updating(static fn () => throw new LogicException('Audit-Log-Einträge sind unveränderlich.'));
        static::deleting(static fn () => throw new LogicException('Audit-Log-Einträge können nicht gelöscht werden.'));
    }
}
