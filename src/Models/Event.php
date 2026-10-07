<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * @property string $id
 * @property Carbon|null $occurred_at
 * @property ?string $ip
 * @property string $ip_hash
 * @property ?string $country
 * @property ?int $asn
 * @property string $method
 * @property ?string $host
 * @property string $path
 * @property ?string $route_name
 * @property ?string $user_agent
 * @property ?string $user_id
 * @property string $mode
 * @property string $outcome
 * @property ?int $status_code
 * @property int $score
 * @property array<int, array<string, mixed>>|null $matches
 * @property ?string $node
 * @property Carbon|null $anonymized_at
 */
class Event extends Model
{
    use HasUlids;

    protected $table = 'waf_events';

    public $timestamps = false;

    protected $fillable = ['id', 'occurred_at', 'ip', 'ip_hash', 'country', 'asn', 'method', 'host', 'path', 'route_name', 'user_agent', 'user_id', 'mode', 'outcome', 'status_code', 'score', 'matches', 'node', 'anonymized_at'];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return ['occurred_at' => 'datetime', 'anonymized_at' => 'datetime', 'matches' => 'array', 'score' => 'integer', 'status_code' => 'integer', 'asn' => 'integer'];
    }
}
