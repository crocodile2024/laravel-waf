<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Alle WAF-Tabellen. Primärschlüssel durchgängig ULID (CHAR 26), Galera-tauglich.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('waf_rules', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->string('code', 64)->unique();
            $t->string('source', 16)->default('custom');
            $t->string('pack', 64)->nullable();
            $t->string('pack_version', 32)->nullable();
            $t->string('name');
            $t->text('description')->nullable();
            $t->string('severity', 16);
            $t->unsignedTinyInteger('paranoia_level')->default(1);
            $t->unsignedSmallInteger('priority')->default(500);
            $t->string('phase', 16)->default('request');
            $t->json('conditions');
            $t->json('transforms')->nullable();
            $t->json('action');
            $t->string('mode_override', 16)->nullable();
            $t->json('tags')->nullable();
            $t->boolean('is_active')->default(true);
            $t->string('created_by', 64)->nullable();
            $t->string('updated_by', 64)->nullable();
            $t->timestamps();
            $t->index(['source', 'is_active']);
        });

        Schema::create('waf_exceptions', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->string('rule_code', 64)->nullable();
            $t->string('rule_tag', 64)->nullable();
            $t->string('scope_type', 16)->default('global');
            $t->string('scope_value')->nullable();
            $t->string('parameter')->nullable();
            $t->string('ip_cidr', 49)->nullable();
            $t->text('comment')->nullable();
            $t->timestamp('expires_at')->nullable();
            $t->string('created_by', 64)->nullable();
            $t->timestamps();
            $t->index(['rule_code', 'scope_type']);
        });

        Schema::create('waf_ip_entries', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->string('list', 8);
            $t->string('cidr', 49);
            $t->binary('ip_start', 16);
            $t->binary('ip_end', 16);
            $t->string('source', 16)->default('manual');
            $t->text('comment')->nullable();
            $t->timestamp('expires_at')->nullable();
            $t->string('created_by', 64)->nullable();
            $t->timestamps();
            $t->index(['list', 'ip_start', 'ip_end']);
        });

        Schema::create('waf_bans', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->string('ip_key', 49);
            $t->string('ip_hash', 64);
            $t->string('reason');
            $t->string('rule_code', 64)->nullable();
            $t->unsignedTinyInteger('level')->default(1);
            $t->timestamp('banned_until')->nullable();
            $t->timestamp('lifted_at')->nullable();
            $t->string('lifted_by', 64)->nullable();
            $t->string('source', 16)->default('auto');
            $t->timestamps();
            $t->index(['ip_key', 'banned_until']);
        });

        Schema::create('waf_rate_limit_profiles', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->string('name', 64)->unique();
            $t->string('key_type', 32)->default('ip');
            $t->string('key_header', 128)->nullable();
            $t->unsignedInteger('limit');
            $t->unsignedInteger('window_seconds');
            $t->unsignedInteger('burst')->default(0);
            $t->json('action');
            $t->boolean('is_active')->default(true);
            $t->timestamps();
        });

        Schema::create('waf_profile_assignments', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->string('profile_type', 16);
            $t->char('profile_id', 26);
            $t->string('match_type', 16);
            $t->string('match_value');
            $t->unsignedSmallInteger('priority')->default(500);
            $t->timestamps();
            $t->index(['profile_type', 'priority']);
        });

        Schema::create('waf_inspection_profiles', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->string('name', 64)->unique();
            $t->unsignedTinyInteger('paranoia_level')->nullable();
            $t->unsignedSmallInteger('inbound_threshold')->nullable();
            $t->string('mode_override', 16)->nullable();
            $t->json('limits')->nullable();
            $t->json('allowed_countries')->nullable();
            $t->json('denied_countries')->nullable();
            $t->json('denied_asns')->nullable();
            $t->json('upload_rules')->nullable();
            $t->timestamps();
        });

        Schema::create('waf_events', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->timestamp('occurred_at', 3)->index();
            $t->string('ip', 45)->nullable();
            $t->string('ip_hash', 64);
            $t->char('country', 2)->nullable();
            $t->unsignedInteger('asn')->nullable();
            $t->string('method', 10);
            $t->string('host')->nullable();
            $t->string('path', 2048);
            $t->string('route_name')->nullable();
            $t->string('user_agent', 512)->nullable();
            $t->string('user_id', 64)->nullable();
            $t->string('mode', 16);
            $t->string('outcome', 16);
            $t->unsignedSmallInteger('status_code')->nullable();
            $t->unsignedInteger('score')->default(0);
            $t->json('matches')->nullable();
            $t->string('node', 128)->nullable();
            $t->timestamp('anonymized_at')->nullable();
            $t->index(['ip_hash', 'occurred_at']);
            $t->index(['outcome', 'occurred_at']);
        });

        Schema::create('waf_stats_hourly', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->timestamp('hour');
            $t->string('outcome', 16);
            $t->string('rule_code', 64)->default('');
            $t->char('country', 2)->default('');
            $t->unsignedInteger('count')->default(0);
            $t->unique(['hour', 'outcome', 'rule_code', 'country']);
        });

        Schema::create('waf_learning_hits', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->string('rule_code', 64);
            $t->string('route_name')->default('');
            $t->string('path_pattern')->nullable();
            $t->string('parameter')->default('');
            $t->unsignedInteger('hit_count')->default(0);
            $t->unsignedInteger('distinct_ip_count')->default(0);
            $t->json('ip_hashes')->nullable();
            $t->timestamp('first_seen_at')->nullable();
            $t->timestamp('last_seen_at')->nullable();
            $t->string('status', 16)->default('open');
            $t->unique(['rule_code', 'route_name', 'parameter']);
        });

        Schema::create('waf_csp_reports', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->date('received_at');
            $t->string('document_uri', 1024)->nullable();
            $t->string('violated_directive')->nullable();
            $t->string('blocked_uri', 1024)->nullable();
            $t->string('source_file', 1024)->nullable();
            $t->unsignedInteger('line')->nullable();
            $t->unsignedInteger('count')->default(1);
            $t->char('fingerprint', 64);
            $t->unique(['received_at', 'fingerprint']);
        });

        Schema::create('waf_settings', function (Blueprint $t): void {
            $t->string('key', 128)->primary();
            $t->json('value');
            $t->string('updated_by', 64)->nullable();
            $t->timestamp('updated_at')->nullable();
        });

        Schema::create('waf_audit_log', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->string('user_id', 64)->nullable();
            $t->string('action', 64);
            $t->string('subject_type', 128)->nullable();
            $t->string('subject_id', 64)->nullable();
            $t->json('changes')->nullable();
            $t->string('ip', 45)->nullable();
            $t->timestamp('created_at')->index();
        });

        Schema::create('waf_notification_channels', function (Blueprint $t): void {
            $t->ulid('id')->primary();
            $t->string('type', 16);
            $t->string('target', 512);
            $t->text('secret')->nullable();
            $t->json('events');
            $t->string('min_severity', 16)->default('warning');
            $t->string('digest', 16)->default('instant');
            $t->boolean('is_active')->default(true);
            $t->timestamps();
        });
    }

    public function down(): void
    {
        foreach ([
            'waf_notification_channels', 'waf_audit_log', 'waf_settings', 'waf_csp_reports', 'waf_learning_hits',
            'waf_stats_hourly', 'waf_events', 'waf_inspection_profiles', 'waf_profile_assignments',
            'waf_rate_limit_profiles', 'waf_bans', 'waf_ip_entries', 'waf_exceptions', 'waf_rules',
        ] as $table) {
            Schema::dropIfExists($table);
        }
    }
};
