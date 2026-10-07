<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

class IpEntry extends Model
{
    use HasUlids;

    protected $table = 'waf_ip_entries';

    public $timestamps = true;

    protected $fillable = ['list', 'cidr', 'ip_start', 'ip_end', 'source', 'comment', 'expires_at', 'created_by'];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return ['expires_at' => 'datetime'];
    }

    /**
     * @param  \Illuminate\Database\Eloquent\Builder<self>  $query
     */
    public function scopeActive(\Illuminate\Database\Eloquent\Builder $query): void
    {
        $query->where(fn ($q) => $q->whereNull('expires_at')->orWhere('expires_at', '>', now()));
    }
}
