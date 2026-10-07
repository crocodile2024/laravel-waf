<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

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
