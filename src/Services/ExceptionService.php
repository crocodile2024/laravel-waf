<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Services;

use Crocodile2024\WAF\Engine\RequestContext;
use Crocodile2024\WAF\Engine\Rules\RuleMatch;
use Crocodile2024\WAF\Models\WafException;
use Crocodile2024\WAF\Support\IpMatcher;
use Illuminate\Support\Str;

/**
 * Verwaltet und prüft Ausnahmen (False-Positive-Handling, 5.5).
 *
 * Ausnahmen werden kompiliert (ohne DB-Zugriff im Hot-Path) und pro Request-Treffer
 * geprüft: (Regel-ID|Tag) × Scope × optional Parameter × optional IP/CIDR.
 */
class ExceptionService
{
    /** @var array<int, array<string, mixed>>|null */
    private ?array $compiled = null;

    public function __construct(
        private readonly ConfigManager $config,
    ) {}

    /**
     * Leere Ausnahmen-Instanz (Tests / Regel-Tester).
     */
    public static function none(): self
    {
        $instance = new self(new ConfigManager(
            new SettingsRepository(app(\Crocodile2024\WAF\Support\RedisStore::class)),
        ));
        $instance->compiled = [];

        return $instance;
    }

    public function covers(RequestContext $ctx, RuleMatch $match): bool
    {
        foreach ($this->rules() as $ex) {
            if ($this->matches($ctx, $match, $ex)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param  array<string, mixed>  $ex
     */
    private function matches(RequestContext $ctx, RuleMatch $match, array $ex): bool
    {
        if ($ex['rule_code'] !== null && $ex['rule_code'] !== $match->ruleCode) {
            return false;
        }
        if ($ex['rule_tag'] !== null && ! in_array($ex['rule_tag'], $match->tags, true)) {
            return false;
        }
        if ($ex['parameter'] !== null && $ex['parameter'] !== '' && $ex['parameter'] !== $match->parameter) {
            return false;
        }
        if ($ex['ip_cidr'] !== null && ! IpMatcher::contains($ex['ip_cidr'], $ctx->ip)) {
            return false;
        }

        switch ($ex['scope_type']) {
            case 'route_name':
                return $ctx->routeName() === $ex['scope_value'];
            case 'path_pattern':
                return $ex['scope_value'] !== null && Str::is($ex['scope_value'], $ctx->path);
            case 'global':
            default:
                return true;
        }
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    public function rules(): array
    {
        return $this->compiled ??= $this->load();
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    private function load(): array
    {
        return WafException::query()->active()->get()->map(static fn (WafException $e): array => [
            'rule_code' => $e->rule_code,
            'rule_tag' => $e->rule_tag,
            'scope_type' => $e->scope_type,
            'scope_value' => $e->scope_value,
            'parameter' => $e->parameter,
            'ip_cidr' => $e->ip_cidr,
        ])->all();
    }

    public function flush(): void
    {
        $this->compiled = null;
    }
}
