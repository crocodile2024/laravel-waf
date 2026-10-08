<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Http\Controllers;

use Crocodile2024\WAF\Engine\RequestContext;
use Crocodile2024\WAF\Events\ChallengePassed;
use Crocodile2024\WAF\Services\CaptchaService;
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
        private readonly CaptchaService $captcha,
        private readonly ConfigManager $config,
    ) {}

    public function show(Request $request): Response
    {
        $ctx = RequestContext::fromRequest($request);
        $target = (string) $request->query('target', '/');

        if ($this->useCaptcha()) {
            return $this->captchaView($ctx, $target);
        }

        $task = $this->challenge->issue($ctx);

        return response()->view('waf::challenge.pow', [
            'incidentId' => $ctx->id,
            'nonce' => $task['nonce'],
            'difficulty' => $task['difficulty'],
            'target' => $target,
            'captchaFallback' => $this->captcha->available(),
            'contact' => $this->config->get('block_page.contact'),
        ], 429);
    }

    /**
     * Bild-Captcha-Seite (expliziter Aufruf oder No-JS-Fallback).
     */
    public function captcha(Request $request): Response
    {
        $ctx = RequestContext::fromRequest($request);

        return $this->captchaView($ctx, (string) $request->query('target', '/'));
    }

    /**
     * Liefert das Captcha-PNG zu einem Token.
     */
    public function captchaImage(Request $request): Response
    {
        $token = (string) $request->query('token', '');
        $png = $this->captcha->render($token);
        if ($png === null) {
            abort(404);
        }

        return response($png, 200, [
            'Content-Type' => 'image/png',
            'Cache-Control' => 'no-store, max-age=0',
            'Pragma' => 'no-cache',
        ]);
    }

    public function solve(Request $request): RedirectResponse
    {
        $validated = $request->validate([
            'mode' => ['nullable', 'in:pow,captcha'],
            'nonce' => ['nullable', 'string', 'max:64'],
            'solution' => ['nullable', 'string', 'max:64'],
            'token' => ['nullable', 'string', 'max:64'],
            'answer' => ['nullable', 'string', 'max:32'],
            'target' => ['nullable', 'string', 'max:2048'],
        ]);

        $ctx = RequestContext::fromRequest($request);
        $target = (string) ($validated['target'] ?? '/');
        $isCaptcha = ($validated['mode'] ?? null) === 'captcha' || ! empty($validated['token']);

        $passed = $isCaptcha
            ? $this->captcha->verify($ctx, (string) ($validated['token'] ?? ''), (string) ($validated['answer'] ?? ''))
            : $this->challenge->verify($ctx, (string) ($validated['nonce'] ?? ''), (string) ($validated['solution'] ?? ''));

        if (! $passed) {
            $route = $isCaptcha ? 'waf.challenge.captcha' : 'waf.challenge.show';

            return redirect()->route($route, ['target' => $target])
                ->withErrors(['challenge' => __('waf::waf.challenge.retry')]);
        }

        Event::dispatch(new ChallengePassed($ctx));

        $pass = $this->challenge->issuePass($ctx);
        $minutes = (int) $this->config->get('challenge.pass_ttl_hours', 12) * 60;

        return redirect()->to($this->safeTarget($request, $target))->withCookie(
            Cookie::make(ChallengeService::COOKIE, $pass, $minutes, '/', null, true, true, false, 'lax')
        );
    }

    private function useCaptcha(): bool
    {
        return $this->config->get('challenge.type', 'pow') === 'captcha' && $this->captcha->available();
    }

    private function captchaView(RequestContext $ctx, string $target): Response
    {
        $token = $this->captcha->issue($ctx);

        return response()->view('waf::challenge.captcha', [
            'incidentId' => $ctx->id,
            'token' => $token,
            'target' => $target,
            'contact' => $this->config->get('block_page.contact'),
        ], 429);
    }

    private function safeTarget(Request $request, string $target): string
    {
        if ($target === '' || ! str_starts_with($target, '/') || str_starts_with($target, '//')) {
            return '/';
        }

        return $target;
    }
}
