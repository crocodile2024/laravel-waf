<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

/**
 * @property string $id
 * @property string $profile_type
 * @property string $profile_id
 * @property string $match_type
 * @property string $match_value
 * @property int $priority
 */
class ProfileAssignment extends Model
{
    use HasUlids;

    protected $table = 'waf_profile_assignments';

    public $timestamps = true;

    protected $fillable = ['profile_type', 'profile_id', 'match_type', 'match_value', 'priority'];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return ['priority' => 'integer'];
    }
}
