<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * @property string $id
 * @property Carbon|null $hour
 * @property string $outcome
 * @property string $rule_code
 * @property string $country
 * @property int $count
 */
class StatHourly extends Model
{
    use HasUlids;

    protected $table = 'waf_stats_hourly';

    public $timestamps = false;

    protected $fillable = ['hour', 'outcome', 'rule_code', 'country', 'count'];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return ['hour' => 'datetime', 'count' => 'integer'];
    }
}
