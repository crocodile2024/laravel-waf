<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

class Ban extends Model
{
    use HasUlids;

    protected $table = 'waf_bans';

    public $timestamps = true;

    protected $fillable = ['ip_key', 'ip_hash', 'reason', 'rule_code', 'level', 'banned_until', 'lifted_at', 'lifted_by', 'source'];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return ['banned_until' => 'datetime', 'lifted_at' => 'datetime', 'level' => 'integer'];
    }

    /**
     * @param  Builder<self>  $query
     */
    public function scopeActive(Builder $query): void
    {
        $query->whereNull('lifted_at')->where(fn ($q) => $q->whereNull('banned_until')->orWhere('banned_until', '>', now()));
    }

    public function isActive(): bool
    {
        return $this->lifted_at === null && ($this->banned_until === null || $this->banned_until->isFuture());
    }
}
