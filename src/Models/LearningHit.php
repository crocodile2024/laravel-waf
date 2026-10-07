<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

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
