<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

class InspectionProfile extends Model
{
    use HasUlids;

    protected $table = 'waf_inspection_profiles';

    public $timestamps = true;

    protected $fillable = ['name', 'paranoia_level', 'inbound_threshold', 'mode_override', 'limits', 'allowed_countries', 'denied_countries', 'denied_asns', 'upload_rules'];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return ['limits' => 'array', 'allowed_countries' => 'array', 'denied_countries' => 'array', 'denied_asns' => 'array', 'upload_rules' => 'array', 'paranoia_level' => 'integer', 'inbound_threshold' => 'integer'];
    }
}
