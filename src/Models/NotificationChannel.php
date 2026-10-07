<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

class NotificationChannel extends Model
{
    use HasUlids;

    protected $table = 'waf_notification_channels';

    public $timestamps = true;

    protected $fillable = ['type', 'target', 'secret', 'events', 'min_severity', 'digest', 'is_active'];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return ['secret' => 'encrypted', 'events' => 'array', 'is_active' => 'boolean'];
    }
}
