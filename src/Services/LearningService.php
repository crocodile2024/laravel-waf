<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Services;

use Crocodile2024\WAF\Engine\RequestContext;
use Crocodile2024\WAF\Engine\Rules\RuleMatch;
use Crocodile2024\WAF\Models\LearningHit;
use Crocodile2024\WAF\Support\Anonymizer;
use Illuminate\Support\Facades\DB;
use Throwable;

/**
 * Sammelt Treffer im Lernmodus gruppiert (Regel × Route × Parameter) für
 * Ausnahme-Vorschläge (5.5).
 */
class LearningService
{
    public function __construct(
        private readonly ConfigManager $config,
    ) {}

    /**
     * @param  array<int, RuleMatch>  $matches
     */
    public function collect(RequestContext $ctx, array $matches): void
    {
        $route = $ctx->routeName() ?? '';
        $ipHash = Anonymizer::hash($ctx->ipKey, $this->config->pepper());

        foreach ($matches as $match) {
            try {
                $this->upsert($match->ruleCode, $route, $ctx->path, (string) $match->parameter, $ipHash);
            } catch (Throwable) {
                // Lernmodus darf den Request nie beeinträchtigen.
            }
        }
    }

    private function upsert(string $ruleCode, string $route, string $path, string $parameter, string $ipHash): void
    {
        DB::transaction(function () use ($ruleCode, $route, $path, $parameter, $ipHash): void {
            /** @var LearningHit $hit */
            $hit = LearningHit::query()->lockForUpdate()->firstOrNew([
                'rule_code' => $ruleCode,
                'route_name' => $route,
                'parameter' => $parameter,
            ]);
            $hashes = $hit->ip_hashes ?? [];
            if (! in_array($ipHash, $hashes, true) && count($hashes) < 50) {
                $hashes[] = $ipHash;
            }
            $hit->path_pattern = $path;
            $hit->hit_count = ($hit->hit_count ?? 0) + 1;
            $hit->ip_hashes = $hashes;
            $hit->distinct_ip_count = count($hashes);
            $hit->first_seen_at ??= now();
            $hit->last_seen_at = now();
            $hit->status ??= 'open';
            $hit->save();
        });
    }
}
