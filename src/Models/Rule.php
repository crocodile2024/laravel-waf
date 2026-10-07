<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

class Rule extends Model
{
    use HasUlids;

    protected $table = 'waf_rules';

    public $timestamps = true;

    protected $fillable = ['code', 'source', 'pack', 'pack_version', 'name', 'description', 'severity', 'paranoia_level', 'priority', 'phase', 'conditions', 'transforms', 'action', 'mode_override', 'tags', 'is_active', 'created_by', 'updated_by'];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return ['conditions' => 'array', 'transforms' => 'array', 'action' => 'array', 'tags' => 'array', 'is_active' => 'boolean', 'paranoia_level' => 'integer', 'priority' => 'integer'];
    }

    public function isCore(): bool
    {
        return $this->source === 'core';
    }

    /**
     * Regel im Format des Regelpakets (Anhang A).
     *
     * @return array<string, mixed>
     */
    public function toDefinition(): array
    {
        return [
            'code' => $this->code,
            'name' => $this->name,
            'description' => $this->description,
            'severity' => $this->severity,
            'paranoia_level' => $this->paranoia_level,
            'priority' => $this->priority,
            'phase' => $this->phase,
            'tags' => $this->tags ?? [],
            'transforms' => $this->transforms ?? [],
            'conditions' => $this->conditions,
            'action' => $this->action,
            'mode_override' => $this->mode_override,
        ];
    }
}
