<?php

declare(strict_types=1);

use Crocodile2024\WAF\Models\NotificationChannel;
use Crocodile2024\WAF\Notifications\WafNotificationMail;
use Crocodile2024\WAF\Services\NotificationService;
use Illuminate\Support\Facades\Mail;

it('sends a styled mailable for an instant mail channel', function () {
    Mail::fake();
    NotificationChannel::query()->create([
        'type' => 'mail', 'target' => 'security@example.de', 'events' => ['ban'],
        'min_severity' => 'notice', 'digest' => 'instant', 'is_active' => true,
    ]);

    app(NotificationService::class)->notify('ban', 'critical', ['ip' => '203.0.113.5', 'reason' => 'Bruteforce']);

    Mail::assertSent(WafNotificationMail::class, function (WafNotificationMail $mail) {
        return $mail->hasTo('security@example.de')
            && $mail->eventType === 'ban'
            && $mail->envelope()->subject === '[WAF] IP gesperrt';
    });
});

it('renders the mail view with payload and ui link', function () {
    config()->set('waf.ui.path', 'admin/waf');
    $mail = new WafNotificationMail('critical_hit', payload: ['ip' => '198.51.100.9', 'rule' => 'WAF-SQLI-002']);
    $rendered = $mail->render();
    expect($rendered)->toContain('Kritischer Treffer')
        ->toContain('WAF-SQLI-002')
        ->toContain('Zur Verwaltungsoberfläche');
});

it('builds a digest mail from collected items', function () {
    $mail = new WafNotificationMail('digest', period: 'daily', items: ['ban: 1.2.3.4', 'critical_hit: /login']);
    $rendered = $mail->render();
    expect($rendered)->toContain('Zusammenfassung (täglich)')->toContain('1.2.3.4');
});
