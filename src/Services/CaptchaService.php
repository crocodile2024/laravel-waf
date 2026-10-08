<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Services;

use Crocodile2024\WAF\Engine\RequestContext;
use Crocodile2024\WAF\Support\RedisStore;
use Illuminate\Support\Str;

/**
 * Bild-Captcha als JavaScript-loser Challenge-Fallback (5.9).
 *
 * Serverseitig mit GD erzeugt, Zeichen ohne Verwechslungsgefahr. Keine
 * Audio-Alternative; stattdessen Hinweis auf Kontakt (in der Blade-Seite).
 */
class CaptchaService
{
    // Ohne 0/O, 1/I/L, etc.
    private const ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';

    public function __construct(
        private readonly RedisStore $redis,
        private readonly ConfigManager $config,
    ) {}

    public function available(): bool
    {
        return function_exists('imagecreatetruecolor');
    }

    /**
     * Erzeugt eine neue Captcha-Aufgabe und liefert deren Token.
     */
    public function issue(RequestContext $ctx, int $length = 5): string
    {
        $code = '';
        for ($i = 0; $i < $length; $i++) {
            $code .= self::ALPHABET[random_int(0, strlen(self::ALPHABET) - 1)];
        }
        $token = Str::random(24);
        $ttl = (int) $this->config->get('challenge.nonce_ttl_seconds', 600);
        $this->redis->set('cap:'.$token, $code.'|'.$this->bindKey($ctx), $ttl);

        return $token;
    }

    public function isCaptchaToken(string $token): bool
    {
        return preg_match('/^[A-Za-z0-9]{1,64}$/', $token) === 1 && $this->redis->exists('cap:'.$token);
    }

    public function verify(RequestContext $ctx, string $token, string $answer): bool
    {
        if (! preg_match('/^[A-Za-z0-9]{1,64}$/', $token)) {
            return false;
        }
        $stored = $this->redis->get('cap:'.$token);
        if ($stored === null || ! str_contains($stored, '|')) {
            return false;
        }
        [$code, $bind] = explode('|', $stored, 2);
        if (! hash_equals($bind, $this->bindKey($ctx))) {
            return false;
        }
        $this->redis->del('cap:'.$token);

        return hash_equals(strtoupper($code), strtoupper(trim($answer)));
    }

    /**
     * Rendert das Captcha-Bild als PNG-Binärstring (oder null, wenn Token ungültig/GD fehlt).
     */
    public function render(string $token): ?string
    {
        if (! $this->available()) {
            return null;
        }
        $stored = $this->redis->get('cap:'.$token);
        if ($stored === null || ! str_contains($stored, '|')) {
            return null;
        }
        $code = explode('|', $stored, 2)[0];

        return $this->draw($code);
    }

    private function draw(string $code): string
    {
        $width = 180;
        $height = 60;
        $image = imagecreatetruecolor($width, $height);

        $bg = (int) imagecolorallocate($image, 245, 244, 240);     // Off-White (Designsystem)
        imagefilledrectangle($image, 0, 0, $width, $height, $bg);

        // Störlinien
        for ($i = 0; $i < 6; $i++) {
            $line = (int) imagecolorallocate($image, random_int(180, 220), random_int(180, 220), random_int(220, 240));
            imageline($image, random_int(0, $width), random_int(0, $height), random_int(0, $width), random_int(0, $height), $line);
        }
        // Störpunkte
        for ($i = 0; $i < 300; $i++) {
            $dot = (int) imagecolorallocate($image, random_int(150, 210), random_int(150, 210), random_int(150, 210));
            imagesetpixel($image, random_int(0, $width), random_int(0, $height), $dot);
        }

        $len = strlen($code);
        $step = (int) (($width - 20) / max(1, $len));
        for ($i = 0; $i < $len; $i++) {
            $ink = (int) imagecolorallocate($image, random_int(40, 90), random_int(40, 90), random_int(90, 160));
            $char = $code[$i];
            $x = 12 + $i * $step;
            $y = random_int(16, 30);
            // Leichte „Rotation" durch versetzte Mehrfachausgabe
            imagestring($image, 5, $x, $y + random_int(-3, 3), $char, $ink);
            imagestring($image, 5, $x + 1, $y + random_int(-2, 2), $char, $ink);
        }

        ob_start();
        imagepng($image);
        $png = (string) ob_get_clean();
        imagedestroy($image);

        return $png;
    }

    private function bindKey(RequestContext $ctx): string
    {
        return $ctx->ipKey.'|'.substr(hash('sha256', $ctx->userAgent), 0, 16);
    }
}
