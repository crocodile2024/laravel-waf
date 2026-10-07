<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Engine;

use Crocodile2024\WAF\Engine\Rules\RuleMatch;
use Crocodile2024\WAF\Services\BanService;
use Crocodile2024\WAF\Services\BotService;
use Crocodile2024\WAF\Services\ConfigManager;
use Crocodile2024\WAF\Services\EventRecorder;
use Crocodile2024\WAF\Services\GeoIpService;
use Crocodile2024\WAF\Services\IpListService;
use Crocodile2024\WAF\Services\LearningService;
use Crocodile2024\WAF\Services\LimitService;
use Crocodile2024\WAF\Services\ProfileResolver;
use Crocodile2024\WAF\Services\RateLimitService;
use Crocodile2024\WAF\Services\ReputationService;
use Crocodile2024\WAF\Services\RuleRegistry;
use Crocodile2024\WAF\Services\UploadInspector;

/**
 * Orchestriert die Prüfung eines Requests entlang der Stufen aus §12.
 *
 * Zustandslos pro Request (Octane-kompatibel): der gesamte Zustand steckt im
 * übergebenen RequestContext und in Redis.
 */
class FirewallEngine
{
    public function __construct(
        private readonly ConfigManager $config,
        private readonly RuleRegistry $rules,
        private readonly Inspector $inspector,
        private readonly IpListService $ipLists,
        private readonly BanService $bans,
        private readonly ReputationService $reputation,
        private readonly GeoIpService $geo,
        private readonly RateLimitService $rateLimits,
        private readonly LimitService $limits,
        private readonly BotService $bots,
        private readonly UploadInspector $uploads,
        private readonly ProfileResolver $profiles,
        private readonly LearningService $learning,
        private readonly EventRecorder $events,
    ) {}

    public function inspect(RequestContext $ctx): Decision
    {
        $mode = $this->resolveMode($ctx);

        // Stufe 4: Allowlist → durchlassen (nur Security-Header gelten weiter)
        if ($this->ipLists->isAllowed($ctx->ip)) {
            return $this->clean($ctx, $mode, count: false, outcome: 'allowed');
        }

        // Stufe 5: Denylist / aktiver Ban → 403
        if ($this->ipLists->isDenied($ctx->ip)) {
            return $this->decide($ctx, Decision::BLOCK, 'denylist', $mode, 403);
        }
        if ($this->bans->isBanned($ctx->ip)) {
            return $this->decide($ctx, Decision::BLOCK, 'ban', $mode, 403);
        }

        // Stufe 6: Geo/ASN
        $this->resolveGeo($ctx);
        if (($geo = $this->profiles->geoDecision($ctx)) !== null) {
            return $this->decide($ctx, Decision::BLOCK, $geo, $mode, 403);
        }

        // Stufe 7: gültiges waf_pass-Cookie
        $ctx->attributes->passCookieValid = $this->bots->hasValidPass($ctx);

        // Stufe 8: Request-Grenzen
        if (($limit = $this->limits->check($ctx)) !== null) {
            return $this->decide($ctx, Decision::BLOCK, $limit['code'], $mode, 400, matches: [$limit['match']]);
        }

        // Stufe 9: Rate-Limits
        if (($rl = $this->rateLimits($ctx, $mode)) !== null) {
            return $rl;
        }

        // Stufe 10: Bot-Prüfungen & Fallen-Routen
        if (($trap = $this->bots->trapRoute($ctx)) !== null) {
            $this->bans->ban($ctx->ip, null, 'Fallen-Route: '.$trap, 'honeypot');

            return $this->decide($ctx, Decision::BLOCK, 'trap', $mode, 403);
        }
        $this->bots->applyScore($ctx);

        // Stufe 11: Normalisierung + Regelauswertung
        $plan = $this->rules->current();
        $learningHits = [];
        $result = $this->inspector->evaluate(
            $ctx,
            $plan->request,
            $this->config->paranoiaLevel(),
            $mode,
            tracer: $mode === Mode::Learning ? function (string $target, ?string $param) use (&$learningHits): void {
                $learningHits[] = [$target, $param];
            } : null,
        );

        if ($result->isAllow()) {
            return $this->clean($ctx, $mode, count: true, outcome: 'allowed');
        }

        $score = $result->score->total();

        // Stufe 12: Upload-Prüfung
        $uploadMatches = $this->uploads->inspect($ctx);
        $matches = [...$result->matches, ...$uploadMatches];
        foreach ($uploadMatches as $m) {
            $score += $m->points;
        }

        // Sofortaktion (block/challenge/ban/rate_limit) einer Regel
        if ($result->immediate !== null && $result->immediate->type !== 'allow') {
            return $this->applyImmediate($ctx, $result->immediate, $matches, $score, $mode);
        }

        // Stufe 13: Score gegen Schwellwert
        $threshold = $this->config->inboundThreshold();
        $tags = $ctx->attributes->tags;

        if ($mode === Mode::Learning && $matches !== []) {
            $this->learning->collect($ctx, $result->matches);
        }

        if ($score >= $threshold && $threshold > 0) {
            // Stufe 14: Reputation + Auto-Ban
            $this->updateReputation($ctx, $score);

            return $this->decide($ctx, Decision::BLOCK, 'score', $mode, 403, $score, $matches);
        }

        if ($matches !== []) {
            $this->updateReputation($ctx, $score);

            return $this->decide($ctx, Decision::PASS, 'score_below', $mode, 200, $score, $matches);
        }

        return $this->clean($ctx, $mode, count: true, outcome: 'logged');
    }

    /**
     * Response-Phase-Regeln (Response-Inspektion, 5.11) gegen einen Response-Kontext.
     *
     * @return array<int, RuleMatch>
     */
    public function inspectResponse(RequestContext $responseCtx): array
    {
        $plan = $this->rules->current();
        $result = $this->inspector->evaluate($responseCtx, $plan->response, 4, Mode::Detect);

        return $result->matches;
    }

    private function rateLimits(RequestContext $ctx, Mode $mode): ?Decision
    {
        foreach ($this->profiles->rateLimitProfiles($ctx) as $profile) {
            $result = $this->rateLimits->hit($profile, $ctx);
            if (! $result->exceeded()) {
                continue;
            }
            $action = (array) ($profile['action'] ?? ['type' => '429']);
            $type = (string) ($action['type'] ?? '429');
            $reason = 'rate_limit:'.$profile['name'];

            if ($type === 'challenge') {
                return $this->decide($ctx, Decision::CHALLENGE, $reason, $mode, 429, retryAfter: $result->retryAfter);
            }
            if ($type === 'ban') {
                if ($mode->enforces()) {
                    $this->bans->ban($ctx->ip, null, 'Rate-Limit: '.$profile['name'], 'auto');
                }

                return $this->decide($ctx, Decision::BLOCK, $reason, $mode, 403);
            }
            if ($type === 'score') {
                $this->reputation->add($ctx->ip, (int) ($action['points'] ?? 5));

                continue;
            }

            return $this->decide($ctx, Decision::RATE_LIMIT, $reason, $mode, 429, retryAfter: $result->retryAfter);
        }

        return null;
    }

    /**
     * @param  array<int, RuleMatch>  $matches
     */
    private function applyImmediate(RequestContext $ctx, ImmediateAction $action, array $matches, int $score, Mode $mode): Decision
    {
        $this->updateReputation($ctx, $score);

        return match ($action->type) {
            'ban' => tap(
                $this->decide($ctx, Decision::BLOCK, $action->ruleCode, $mode, 403, $score, $matches, $action->ruleCode),
                fn () => $action->enforced() ? $this->bans->ban($ctx->ip, $action->banMinutes(), 'Regel '.$action->ruleCode, 'auto', $action->ruleCode) : null,
            ),
            'challenge' => $this->decide($ctx, Decision::CHALLENGE, $action->ruleCode, $mode, 429, $score, $matches, $action->ruleCode),
            'rate_limit' => $this->decide($ctx, Decision::RATE_LIMIT, $action->ruleCode, $mode, 429, $score, $matches, $action->ruleCode),
            default => $this->decide($ctx, Decision::BLOCK, $action->ruleCode, $mode, $action->status(), $score, $matches, $action->ruleCode),
        };
    }

    private function updateReputation(RequestContext $ctx, int $score): void
    {
        if ($score <= 0) {
            return;
        }
        $total = $this->reputation->add($ctx->ip, $score);
        if ($total >= $this->reputation->banThreshold() && $this->config->mode() === Mode::Block) {
            $this->bans->ban($ctx->ip, null, 'Reputation überschritten', 'auto');
        }
    }

    private function resolveMode(RequestContext $ctx): Mode
    {
        return $this->profiles->modeFor($ctx, $this->config->mode());
    }

    private function resolveGeo(RequestContext $ctx): void
    {
        if ($ctx->attributes->geoResolved || ! $this->geo->available()) {
            return;
        }
        $ctx->attributes->country = $this->geo->country($ctx->ip);
        $ctx->attributes->asn = $this->geo->asn($ctx->ip);
        $ctx->attributes->geoResolved = true;
    }

    private function clean(RequestContext $ctx, Mode $mode, bool $count, string $outcome): Decision
    {
        if ($count) {
            $this->events->countClean();
        }

        return new Decision(Decision::ALLOW, $ctx, $outcome, 200, enforced: $mode->enforces());
    }

    /**
     * @param  array<int, RuleMatch>  $matches
     */
    private function decide(
        RequestContext $ctx,
        string $type,
        ?string $reason,
        Mode $mode,
        int $status,
        int $score = 0,
        array $matches = [],
        ?string $ruleCode = null,
        ?int $retryAfter = null,
    ): Decision {
        $enforced = $mode->enforces();
        $outcome = match ($type) {
            Decision::BLOCK => 'blocked',
            Decision::CHALLENGE => 'challenged',
            Decision::RATE_LIMIT => 'blocked',
            default => 'logged',
        };
        if (! $enforced && $type !== Decision::PASS) {
            $outcome = 'logged';
        }

        return new Decision($type, $ctx, $outcome, $status, $score, $matches, $ruleCode ?? $reason, $retryAfter, $enforced);
    }
}
