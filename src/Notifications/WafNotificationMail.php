<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Mail\Mailable;
use Illuminate\Mail\Mailables\Content;
use Illuminate\Mail\Mailables\Envelope;
use Illuminate\Queue\SerializesModels;

/**
 * Gestylte Benachrichtigungs-Mail im Designsystem (Deutsch), mit Link in die UI.
 */
class WafNotificationMail extends Mailable
{
    use Queueable, SerializesModels;

    /**
     * @param  array<string, mixed>  $payload
     * @param  array<int, string>  $items  (für Digest)
     */
    public function __construct(
        public readonly string $eventType,
        public readonly array $payload = [],
        public readonly ?string $period = null,
        public readonly array $items = [],
    ) {}

    public function envelope(): Envelope
    {
        $label = self::label($this->eventType);
        $prefix = $this->period !== null ? '[WAF-Digest] ' : '[WAF] ';

        return new Envelope(subject: $prefix.$label);
    }

    public function content(): Content
    {
        return new Content(view: 'waf::mail.notification', with: [
            'eventType' => $this->eventType,
            'label' => self::label($this->eventType),
            'description' => self::description($this->eventType),
            'payload' => $this->payload,
            'period' => $this->period,
            'items' => $this->items,
            'uiUrl' => self::uiUrl(),
            'occurredAt' => now()->format('d.m.Y H:i:s'),
        ]);
    }

    public static function label(string $eventType): string
    {
        return match ($eventType) {
            'ban' => 'IP gesperrt',
            'attack_wave' => 'Angriffswelle erkannt',
            'critical_hit' => 'Kritischer Treffer',
            'mode_change' => 'Modus geändert',
            'config_change' => 'Konfiguration geändert',
            'redis_down' => 'Redis nicht erreichbar',
            'geoip_stale' => 'GeoIP-Datenbank veraltet',
            'digest' => 'Zusammenfassung',
            default => 'Ereignis',
        };
    }

    public static function description(string $eventType): string
    {
        return match ($eventType) {
            'ban' => 'Eine IP-Adresse wurde von der Firewall gesperrt.',
            'attack_wave' => 'Die Firewall hat eine erhöhte Zahl blockierter Anfragen festgestellt.',
            'critical_hit' => 'Eine Anfrage hat eine kritische Regel ausgelöst.',
            'mode_change' => 'Der Betriebsmodus der WAF wurde geändert.',
            'config_change' => 'Die WAF-Konfiguration wurde geändert.',
            'redis_down' => 'Die Laufzeitdatenbank (Redis) ist nicht erreichbar – es gilt das konfigurierte Fail-Verhalten.',
            'geoip_stale' => 'Die lokale GeoIP-Datenbank ist veraltet und sollte aktualisiert werden.',
            default => 'Die Web Application Firewall meldet ein Ereignis.',
        };
    }

    private static function uiUrl(): ?string
    {
        try {
            $path = (string) config('waf.ui.path', 'admin/waf');

            return url($path);
        } catch (\Throwable) {
            return null;
        }
    }
}
