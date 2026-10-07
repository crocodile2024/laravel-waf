<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * @property string $id
 * @property ?string $rule_code
 * @property ?string $rule_tag
 * @property string $scope_type
 * @property ?string $scope_value
 * @property ?string $parameter
 * @property ?string $ip_cidr
 * @property ?string $comment
 * @property Carbon|null $expires_at
 * @property ?string $created_by
 */
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
