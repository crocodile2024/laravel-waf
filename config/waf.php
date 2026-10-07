<?php

declare(strict_types=1);

return [

    /*
    |--------------------------------------------------------------------------
    | Grundeinstellungen
    |--------------------------------------------------------------------------
    |
    | Rangfolge: waf_settings (UI) > .env/Config > Paket-Standard.
    | Sicherheitskritische Schlüssel (pepper, redis, ui.middleware, ui.gate,
    | fail_mode) sind nur hier änderbar, nicht über die Oberfläche.
    |
    */

    'enabled' => env('WAF_ENABLED', true),
    'mode' => env('WAF_MODE', 'detect'),           // off|learning|detect|block
    'fail_mode' => env('WAF_FAIL_MODE', 'open'),   // open|closed
    'paranoia_level' => (int) env('WAF_PARANOIA', 1),
    'inbound_threshold' => (int) env('WAF_THRESHOLD', 5),
    'pepper' => env('WAF_PEPPER'),

    'redis' => [
        'connection' => env('WAF_REDIS_CONNECTION', 'default'),
        'prefix' => env('WAF_REDIS_PREFIX', 'waf:'),
    ],

    'ui' => [
        'enabled' => env('WAF_UI_ENABLED', true),
        'path' => env('WAF_UI_PATH', 'admin/waf'),
        'domain' => env('WAF_UI_DOMAIN'),
        'middleware' => ['web', 'auth', 'verified'],
        'gate' => 'viewWAF',
        // Rate-Limit für die UI selbst (Requests pro Minute je IP)
        'rate_limit' => 300,
    ],

    'inspection' => [
        'max_body_bytes' => 65536,
        'json_max_depth' => 32,
        'excluded_paths' => ['up'],
        'inspect_headers' => ['user-agent', 'referer', 'x-forwarded-host', 'origin', 'content-type'],
        // Zusätzliche, von der Host-App registrierte Stages (Klassennamen)
        'stages' => [],
    ],

    /*
    | Request-Grenzen (5.12) – global, pro Profil überschreibbar.
    */
    'limits' => [
        'allowed_methods' => ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
        'max_url_length' => 4096,
        'max_header_bytes' => 8192,
        'max_header_count' => 100,
        'max_params' => 500,
        'max_param_length' => 65536,
        'max_body_bytes' => 10 * 1024 * 1024,
        'allowed_content_types' => [
            'application/x-www-form-urlencoded',
            'multipart/form-data',
            'application/json',
            'application/*+json',
            'text/plain',
            'application/xml',
            'text/xml',
            'application/csp-report',
            'application/reports+json',
        ],
        // Leer = keine Host-Prüfung
        'allowed_hosts' => [],
    ],

    'reputation' => [
        'half_life_minutes' => 60,
        'ban_threshold' => 50,
    ],

    'bans' => [
        'escalation' => [15, 60, 1440, 10080],   // Minuten
        'reset_after_days' => 30,
        'ipv6_prefix' => 64,
    ],

    'rate_limit' => [
        'send_headers' => true,
        'login' => [
            'enabled' => true,
            'challenge_after' => 5,
            'ban_after' => 15,
            'window_seconds' => 900,
        ],
        'not_found' => [
            'enabled' => true,
            'limit' => 30,
            'window_seconds' => 60,
            'score' => 10,
        ],
        'errors' => [
            'enabled' => true,
            'limit' => 60,
            'window_seconds' => 60,
            'score' => 5,
        ],
    ],

    'bots' => [
        'block_empty_user_agent' => false,
        'verify_search_engines' => true,
        'trap_paths' => ['wp-login.php', 'xmlrpc.php', 'wp-admin/install.php'],
        'honeypot_min_seconds' => 2,
    ],

    'challenge' => [
        'type' => 'pow',          // pow|captcha
        'pow_difficulty' => 18,
        'pass_ttl_hours' => 12,
        'nonce_ttl_seconds' => 600,
    ],

    'uploads' => [
        'enabled' => true,
        'allowed_extensions' => ['jpg', 'jpeg', 'png', 'gif', 'webp', 'pdf', 'txt', 'csv', 'zip', 'docx', 'xlsx', 'odt', 'ods'],
        'allowed_mimes' => [],
        'max_file_bytes' => 20 * 1024 * 1024,
        'max_files' => 20,
        'max_compression_ratio' => 100,
    ],

    'geoip' => [
        'country_db' => storage_path('app/waf/GeoLite2-Country.mmdb'),
        'asn_db' => storage_path('app/waf/GeoLite2-ASN.mmdb'),
        'license_key' => env('WAF_MAXMIND_LICENSE'),
        'auto_update' => false,
        'allowed_countries' => [],
        'denied_countries' => [],
        'denied_asns' => [],
    ],

    'clamav' => [
        'enabled' => false,
        'socket' => 'unix:///var/run/clamav/clamd.ctl',
        'timeout' => 5,
    ],

    /*
    | Security-Header (5.11) – jeweils enabled + value.
    */
    'headers' => [
        'enabled' => true,
        'csp' => [
            'enabled' => false,
            'report_only' => true,
            'directives' => [
                'default-src' => ["'self'"],
                'script-src' => ["'self'", "'nonce'"],
                'style-src' => ["'self'", "'nonce'"],
                'img-src' => ["'self'", 'data:'],
                'font-src' => ["'self'"],
                'connect-src' => ["'self'"],
                'frame-ancestors' => ["'self'"],
                'base-uri' => ["'self'"],
                'form-action' => ["'self'"],
                'object-src' => ["'none'"],
            ],
            'report_uri' => true,
        ],
        'hsts' => ['enabled' => true, 'max_age' => 31536000, 'include_subdomains' => true, 'preload' => false],
        'x_content_type_options' => ['enabled' => true, 'value' => 'nosniff'],
        'x_frame_options' => ['enabled' => true, 'value' => 'SAMEORIGIN'],
        'referrer_policy' => ['enabled' => true, 'value' => 'strict-origin-when-cross-origin'],
        'permissions_policy' => ['enabled' => true, 'value' => 'camera=(), microphone=(), geolocation=(), payment=()'],
        'coop' => ['enabled' => true, 'value' => 'same-origin'],
        'corp' => ['enabled' => true, 'value' => 'same-origin'],
        'remove_powered_by' => true,
        'remove_server' => true,
        'cookies' => [
            'enabled' => true,
            'secure' => true,
            'http_only' => true,
            'same_site' => 'lax',
            // Cookies, die für JavaScript lesbar bleiben müssen
            'http_only_allowlist' => ['XSRF-TOKEN'],
        ],
    ],

    'response_inspection' => [
        'enabled' => false,
        'max_bytes' => 524288,
        'action' => 'log',   // log|replace
    ],

    'privacy' => [
        'anonymize_after_days' => 7,
        'retention_days' => 30,
        'stats_retention_days' => 400,
        'store_user_id' => false,
        'redact_keys' => ['password', 'passwort', 'token', 'secret', 'api_key', 'authorization', 'cookie', 'iban', 'credit_card', 'cvc', '_token'],
    ],

    'block_page' => [
        'contact' => env('WAF_CONTACT'),
    ],

    'events' => [
        'flush_batch' => 500,
        'max_queue_length' => 100000,
    ],

    'blocklists' => [
        'enabled' => false,
        'urls' => [],
    ],

    'notifications' => [
        'attack_wave_per_minute' => 100,
        'throttle_minutes' => 10,
    ],

    'schedule' => [
        'enabled' => true,
    ],

    'cluster' => [
        'heartbeat_ttl' => 120,
        'node_name' => env('WAF_NODE_NAME'),
    ],
];
