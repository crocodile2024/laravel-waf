<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Http\Middleware;

use Closure;
use Crocodile2024\WAF\Engine\Decision;
use Crocodile2024\WAF\Engine\FirewallEngine;
use Crocodile2024\WAF\Engine\RequestContext;
use Crocodile2024\WAF\Events\RequestBlocked;
use Crocodile2024\WAF\Events\RequestChallenged;
use Crocodile2024\WAF\Http\Responses\BlockResponseFactory;
use Crocodile2024\WAF\Services\ConfigManager;
use Crocodile2024\WAF\Services\EventRecorder;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * Globale WAF-Middleware (an den Anfang der Kette gehängt, §3).
 */
class Firewall
{
    public function __construct(
        private readonly ConfigManager $config,
        private readonly FirewallEngine $engine,
        private readonly EventRecorder $events,
        private readonly BlockResponseFactory $responses,
    ) {}

    public function handle(Request $request, Closure $next, string ...$params): Response
    {
        if (! $this->config->enabled() || $this->config->mode()->value === 'off') {
            return $next($request);
        }
        if ($this->isExcluded($request)) {
            return $next($request);
        }

        try {
            $ctx = $this->buildContext($request, $params);
        } catch (Throwable $e) {
            // Prüfung konnte nicht aufgebaut werden → fail_mode
            if ($this->config->failClosed()) {
                return $this->responses->serverUnavailable();
            }

            return $next($request);
        }

        $request->attributes->set('waf.context', $ctx);

        try {
            $decision = $this->engine->inspect($ctx);
        } catch (Throwable $e) {
            report($e);
            if ($this->config->failClosed()) {
                return $this->responses->serverUnavailable();
            }

            return $next($request);
        }

        $this->recordDecision($ctx, $decision);

        if ($decision->shouldBlock()) {
            return $this->buildResponse($ctx, $decision);
        }

        return $next($request);
    }

    private function buildContext(Request $request, array $params): RequestContext
    {
        $ctx = RequestContext::fromRequest($request, [
            'max_body_bytes' => (int) $this->config->get('inspection.max_body_bytes', 65536),
            'json_max_depth' => (int) $this->config->get('inspection.json_max_depth', 32),
            'ipv6_prefix' => (int) $this->config->get('bans.ipv6_prefix', 64),
        ]);
        // Middleware-Parameter (z. B. waf:profile,login) in den Kontext spiegeln
        foreach ($params as $param) {
            if (str_starts_with($param, 'profile,') || str_starts_with($param, 'profile:')) {
                $ctx->attributes->profile = substr($param, 8);
            }
        }

        return $ctx;
    }

    private function recordDecision(RequestContext $ctx, Decision $decision): void
    {
        if ($decision->type === Decision::ALLOW && $decision->matches === []) {
            return;
        }

        $this->events->record(
            $ctx,
            $decision->outcome,
            $this->config->mode()->value,
            $decision->shouldBlock() ? $decision->status : null,
            $decision->score,
            $decision->matches,
        );

        if ($decision->shouldBlock()) {
            if ($decision->type === Decision::CHALLENGE) {
                Event::dispatch(new RequestChallenged($ctx, array_map(fn ($m) => $m->toArray(), $decision->matches), $decision->score));
            } else {
                Event::dispatch(new RequestBlocked($ctx, array_map(fn ($m) => $m->toArray(), $decision->matches), $decision->score, $decision->status));
            }
        }
    }

    private function buildResponse(RequestContext $ctx, Decision $decision): Response
    {
        return match ($decision->type) {
            Decision::CHALLENGE => $this->responses->challenge($ctx, $decision),
            Decision::RATE_LIMIT => $this->responses->rateLimited($ctx, $decision),
            default => $this->responses->blocked($ctx, $decision),
        };
    }

    private function isExcluded(Request $request): bool
    {
        $path = trim($request->path(), '/');
        $excluded = (array) $this->config->get('inspection.excluded_paths', ['up']);
        $uiPath = trim((string) config('waf.ui.path', 'admin/waf'), '/');
        $excluded[] = $uiPath;
        $excluded[] = $uiPath.'/*';
        $excluded[] = 'waf/challenge';
        $excluded[] = 'waf/challenge/*';
        $excluded[] = 'waf/csp-report';

        foreach ($excluded as $pattern) {
            $pattern = trim((string) $pattern, '/');
            if ($pattern !== '' && ($path === $pattern || Str::is($pattern, $path))) {
                return true;
            }
        }

        return false;
    }
}
