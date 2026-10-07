<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * @property string $id
 * @property string $rule_code
 * @property string $route_name
 * @property ?string $path_pattern
 * @property string $parameter
 * @property int $hit_count
 * @property int $distinct_ip_count
 * @property array<int, string>|null $ip_hashes
 * @property Carbon|null $first_seen_at
 * @property Carbon|null $last_seen_at
 * @property string $status
 */
class LearningHit extends Model
{
    use HasUlids;

    protected $table = 'waf_learning_hits';

    public $timestamps = false;

    protected $fillable = ['rule_code', 'route_name', 'path_pattern', 'parameter', 'hit_count', 'distinct_ip_count', 'ip_hashes', 'first_seen_at', 'last_seen_at', 'status'];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return ['ip_hashes' => 'array', 'first_seen_at' => 'datetime', 'last_seen_at' => 'datetime', 'hit_count' => 'integer', 'distinct_ip_count' => 'integer'];
    }

    public function isSuspicious(): bool
    {
        return $this->distinct_ip_count <= 1;
    }
}
