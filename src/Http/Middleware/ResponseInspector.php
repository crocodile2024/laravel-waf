<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Http\Middleware;

use Closure;
use Crocodile2024\WAF\Engine\FirewallEngine;
use Crocodile2024\WAF\Engine\RequestContext;
use Crocodile2024\WAF\Services\ConfigManager;
use Crocodile2024\WAF\Services\EventRecorder;
use Crocodile2024\WAF\Services\RateLimitService;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Response-Inspektion (5.11) und 404-/Fehler-Zähler (5.8). Standardmäßig aus.
 */
class ResponseInspector
{
    public function __construct(
        private readonly ConfigManager $config,
        private readonly FirewallEngine $engine,
        private readonly EventRecorder $events,
        private readonly RateLimitService $rateLimits,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);

        /** @var RequestContext|null $ctx */
        $ctx = $request->attributes->get('waf.context');
        if ($ctx === null) {
            return $response;
        }

        $this->trackErrors($ctx, $response->getStatusCode());

        if (! $this->config->get('response_inspection.enabled', false)) {
            return $response;
        }

        $contentType = strtolower((string) $response->headers->get('Content-Type', ''));
        if (! str_contains($contentType, 'text/html') && ! str_contains($contentType, 'application/json')) {
            return $response;
        }

        $content = (string) $response->getContent();
        $maxBytes = (int) $this->config->get('response_inspection.max_bytes', 524288);
        if ($content === '' || strlen($content) > $maxBytes) {
            return $response;
        }

        $responseCtx = RequestContext::make(['raw_body' => $content, 'path' => $ctx->path]);
        $matches = $this->engine->inspectResponse($responseCtx);

        if ($matches !== []) {
            $this->events->record($ctx, 'logged', $this->config->mode()->value, $response->getStatusCode(), 0, $matches);

            if ($this->config->get('response_inspection.action') === 'replace') {
                return response()->view('waf::block', [
                    'incidentId' => $ctx->id,
                    'status' => 500,
                    'contact' => $this->config->get('block_page.contact'),
                ], 500);
            }
        }

        return $response;
    }

    private function trackErrors(RequestContext $ctx, int $status): void
    {
        if ($status === 404 && $this->config->get('rate_limit.not_found.enabled', true)) {
            $window = (int) $this->config->get('rate_limit.not_found.window_seconds', 60);
            $limit = (int) $this->config->get('rate_limit.not_found.limit', 30);
            if ($this->rateLimits->countInWindow('404:'.$ctx->ipKey, $window) > $limit) {
                app(\Crocodile2024\WAF\Services\ReputationService::class)->add($ctx->ip, (int) $this->config->get('rate_limit.not_found.score', 10));
            }
        } elseif ($status >= 400 && $this->config->get('rate_limit.errors.enabled', true)) {
            $window = (int) $this->config->get('rate_limit.errors.window_seconds', 60);
            $limit = (int) $this->config->get('rate_limit.errors.limit', 60);
            if ($this->rateLimits->countInWindow('4xx:'.$ctx->ipKey, $window) > $limit) {
                app(\Crocodile2024\WAF\Services\ReputationService::class)->add($ctx->ip, (int) $this->config->get('rate_limit.errors.score', 5));
            }
        }
    }
}
