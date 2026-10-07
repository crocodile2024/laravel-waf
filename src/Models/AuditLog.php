<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use LogicException;

/**
 * Unveränderlicher Audit-Log-Eintrag (kein Update/Delete über das Model).
 */
/**
 * @property string $id
 * @property ?string $user_id
 * @property string $action
 * @property ?string $subject_type
 * @property ?string $subject_id
 * @property array<string, mixed>|null $changes
 * @property ?string $ip
 * @property Carbon|null $created_at
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
