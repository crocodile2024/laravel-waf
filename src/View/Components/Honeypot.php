<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\View\Components;

use Crocodile2024\WAF\Services\BotService;
use Illuminate\Contracts\View\View;
use Illuminate\View\Component;

/**
 * Formular-Honeypot (5.9): <x-waf::honeypot />.
 *
 * Fügt ein verstecktes Feld (Köder) und einen signierten Zeitstempel ein.
 * Ausgefülltes Feld oder zu schnelles Absenden wird von der WAF erkannt.
 */
class Honeypot extends Component
{
    public string $token;

    public function __construct(BotService $bots)
    {
        $this->token = $bots->honeypotToken();
    }

    public function render(): View
    {
        return view('waf::components.honeypot');
    }
}
