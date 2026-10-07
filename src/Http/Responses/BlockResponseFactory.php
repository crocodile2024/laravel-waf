<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Http\Responses;

use Crocodile2024\WAF\Engine\Decision;
use Crocodile2024\WAF\Engine\RequestContext;
use Crocodile2024\WAF\Services\ChallengeService;
use Crocodile2024\WAF\Services\ConfigManager;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Response;
use Symfony\Component\HttpFoundation\Response as BaseResponse;

/**
 * Erzeugt Block-, Challenge- und Rate-Limit-Antworten (5.13). Keine Angabe von
 * Regel oder Grund; nur Vorfall-ID.
 */
class BlockResponseFactory
{
    public function __construct(
        private readonly ConfigManager $config,
        private readonly ChallengeService $challenge,
    ) {}

    public function blocked(RequestContext $ctx, Decision $decision): BaseResponse
    {
        return $this->render($ctx, $decision->status, 'block', 'request_blocked');
    }

    public function rateLimited(RequestContext $ctx, Decision $decision): BaseResponse
    {
        $response = $this->render($ctx, 429, 'ratelimit', 'rate_limited', ['Retry-After' => (string) max(1, (int) $decision->retryAfter)]);

        return $response;
    }

    public function challenge(RequestContext $ctx, Decision $decision): BaseResponse
    {
        // API/JSON → 429 statt interaktiver Challenge
        if (! $ctx->acceptsHtml) {
            return $this->render($ctx, 429, 'ratelimit', 'challenge_required', ['Retry-After' => (string) max(1, (int) $decision->retryAfter)]);
        }

        $task = $this->challenge->issue($ctx);

        return response()->view('waf::challenge.pow', [
            'incidentId' => $ctx->id,
            'nonce' => $task['nonce'],
            'difficulty' => $task['difficulty'],
            'target' => $ctx->uri,
            'contact' => $this->config->get('block_page.contact'),
        ], 429);
    }

    public function serverUnavailable(): BaseResponse
    {
        return response()->view('waf::block', [
            'incidentId' => '-',
            'status' => 503,
            'contact' => $this->config->get('block_page.contact'),
        ], 503);
    }

    /**
     * @param  array<string, string>  $headers
     */
    private function render(RequestContext $ctx, int $status, string $view, string $error, array $headers = []): BaseResponse
    {
        if (! $ctx->acceptsHtml) {
            return new JsonResponse([
                'error' => $error,
                'incident_id' => $ctx->id,
            ], $status, $headers);
        }

        return response()->view('waf::block', [
            'incidentId' => $ctx->id,
            'status' => $status,
            'contact' => $this->config->get('block_page.contact'),
        ], $status, $headers);
    }
}
