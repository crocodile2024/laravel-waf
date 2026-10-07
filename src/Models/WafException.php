<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

class WafException extends Model
{
    use HasUlids;

    protected $table = 'waf_exceptions';

    public $timestamps = true;

    protected $fillable = ['rule_code', 'rule_tag', 'scope_type', 'scope_value', 'parameter', 'ip_cidr', 'comment', 'expires_at', 'created_by'];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return ['expires_at' => 'datetime'];
    }

    /**
     * @param  Builder<self>  $query
     */
    public function scopeActive(Builder $query): void
    {
        $query->where(fn ($q) => $q->whereNull('expires_at')->orWhere('expires_at', '>', now()));
    }
}
