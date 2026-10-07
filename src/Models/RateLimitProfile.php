<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

class RateLimitProfile extends Model
{
    use HasUlids;

    protected $table = 'waf_rate_limit_profiles';

    public $timestamps = true;

    protected $fillable = ['name', 'key_type', 'key_header', 'limit', 'window_seconds', 'burst', 'action', 'is_active'];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return ['action' => 'array', 'is_active' => 'boolean', 'limit' => 'integer', 'window_seconds' => 'integer', 'burst' => 'integer'];
    }
}
