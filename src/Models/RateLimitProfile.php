<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

/**
 * @property string $id
 * @property string $name
 * @property string $key_type
 * @property ?string $key_header
 * @property int $limit
 * @property int $window_seconds
 * @property int $burst
 * @property array<string, mixed> $action
 * @property bool $is_active
 */
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
