<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

class CspReport extends Model
{
    use HasUlids;

    protected $table = 'waf_csp_reports';

    public $timestamps = false;

    protected $fillable = ['received_at', 'document_uri', 'violated_directive', 'blocked_uri', 'source_file', 'line', 'count', 'fingerprint'];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return ['received_at' => 'date', 'count' => 'integer', 'line' => 'integer'];
    }
}
