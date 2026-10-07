<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * @property string $key
 * @property mixed $value
 * @property ?string $updated_by
 * @property Carbon|null $updated_at
 */
class Setting extends Model
{
    protected $table = 'waf_settings';

    protected $primaryKey = 'key';

    protected $keyType = 'string';

    public $incrementing = false;

    public const CREATED_AT = null;

    protected $fillable = ['key', 'value', 'updated_by'];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return ['value' => 'json'];
    }
}
