<?php

declare(strict_types=1);

use Crocodile2024\WAF\Services\RuleImporter;
use Crocodile2024\WAF\Services\RuleRegistry;

it('engine stays within the p95 latency budget', function () {
    app(RuleImporter::class)->importCorePack();
    app(RuleRegistry::class)->recompile();

    $exit = $this->artisan('waf:benchmark', ['--iterations' => 1500, '--max-p95' => 2.0]);
    $exit->assertExitCode(0);
});
