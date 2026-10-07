<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Http\Controllers;

use Crocodile2024\WAF\Engine\RequestContext;
use Crocodile2024\WAF\Events\ChallengePassed;
use Crocodile2024\WAF\Services\ChallengeService;
use Crocodile2024\WAF\Services\ConfigManager;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\Event;
use Symfony\Component\HttpFoundation\Response;

class ChallengeController extends Controller
{
    public function __construct(
        private readonly ChallengeService $challenge,
        private readonly ConfigManager $config,
    ) {}

    public function show(Request $request): Response
    {
        $ctx = RequestContext::fromRequest($request);
        $task = $this->challenge->issue($ctx);

        return response()->view('waf::challenge.pow', [
            'incidentId' => $ctx->id,
            'nonce' => $task['nonce'],
            'difficulty' => $task['difficulty'],
            'target' => $request->query('target', '/'),
            'contact' => $this->config->get('block_page.contact'),
        ], 429);
    }

    public function solve(Request $request): RedirectResponse
    {
        $validated = $request->validate([
            'nonce' => ['required', 'string', 'max:64'],
            'solution' => ['required', 'string', 'max:64'],
            'target' => ['nullable', 'string', 'max:2048'],
        ]);

        $ctx = RequestContext::fromRequest($request);
        if (! $this->challenge->verify($ctx, $validated['nonce'], $validated['solution'])) {
            return redirect()->route('waf.challenge.show', ['target' => $validated['target'] ?? '/'])
                ->withErrors(['challenge' => __('waf::waf.challenge.retry')]);
        }

        Event::dispatch(new ChallengePassed($ctx));

        $pass = $this->challenge->issuePass($ctx);
        $minutes = (int) $this->config->get('challenge.pass_ttl_hours', 12) * 60;
        $target = $this->safeTarget($request, (string) ($validated['target'] ?? '/'));

        return redirect()->to($target)->withCookie(
            Cookie::make(ChallengeService::COOKIE, $pass, $minutes, '/', null, true, true, false, 'lax')
        );
    }

    private function safeTarget(Request $request, string $target): string
    {
        if ($target === '' || ! str_starts_with($target, '/') || str_starts_with($target, '//')) {
            return '/';
        }

        return $target;
    }
}
