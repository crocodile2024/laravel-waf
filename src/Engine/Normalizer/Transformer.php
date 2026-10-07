<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Engine\Normalizer;

use InvalidArgumentException;
use Normalizer as IntlNormalizer;

/**
 * Transformationskette zur Normalisierung von Prüfwerten (5.1).
 *
 * Alle Funktionen sind zustandslos und arbeiten bytesicher; ungültiges UTF-8
 * führt nie zu einem Abbruch der Prüfung.
 */
final class Transformer
{
    public const TRANSFORMS = [
        'urlDecodeUni',
        'htmlEntityDecode',
        'lowercase',
        'removeNulls',
        'compressWhitespace',
        'removeWhitespace',
        'removeComments',
        'normalizePath',
        'utf8Normalize',
        'base64DecodeIfValid',
        'jsDecode',
        'cssDecode',
        'hexDecode',
        'cmdLine',
    ];

    /** @var array<string, string> */
    private array $memo = [];

    public static function isValid(string $name): bool
    {
        return in_array($name, self::TRANSFORMS, true);
    }

    /**
     * Wendet eine Kette an. Ergebnisse werden pro Instanz (= pro Request) zwischengespeichert.
     *
     * @param  array<int, string>  $chain
     */
    public function apply(string $value, array $chain): string
    {
        if ($chain === [] || $value === '') {
            return $value;
        }

        $key = implode(',', $chain)."\0".(strlen($value) > 256 ? md5($value) : $value);
        if (isset($this->memo[$key])) {
            return $this->memo[$key];
        }

        $result = $value;
        foreach ($chain as $name) {
            $result = self::single($name, $result);
        }

        if (count($this->memo) > 5000) {
            $this->memo = [];
        }

        return $this->memo[$key] = $result;
    }

    /**
     * Wendet eine Kette an und protokolliert jeden Zwischenschritt (für den Regel-Tester).
     *
     * @param  array<int, string>  $chain
     * @return array<int, array{transform: string, value: string}>
     */
    public static function trace(string $value, array $chain): array
    {
        $steps = [['transform' => 'original', 'value' => $value]];
        foreach ($chain as $name) {
            $value = self::single($name, $value);
            $steps[] = ['transform' => $name, 'value' => $value];
        }

        return $steps;
    }

    public static function single(string $name, string $value): string
    {
        return match ($name) {
            'urlDecodeUni' => self::urlDecodeUni($value),
            'htmlEntityDecode' => self::htmlEntityDecode($value),
            'lowercase' => strtolower($value),
            'removeNulls' => str_replace("\0", '', $value),
            'compressWhitespace' => self::compressWhitespace($value),
            'removeWhitespace' => (string) preg_replace('/[\s\x0b]+/', '', $value),
            'removeComments' => self::removeComments($value),
            'normalizePath' => self::normalizePath($value),
            'utf8Normalize' => self::utf8Normalize($value),
            'base64DecodeIfValid' => self::base64DecodeIfValid($value),
            'jsDecode' => self::jsDecode($value),
            'cssDecode' => self::cssDecode($value),
            'hexDecode' => self::hexDecode($value),
            'cmdLine' => self::cmdLine($value),
            default => throw new InvalidArgumentException("Unbekannte Transformation: {$name}"),
        };
    }

    /**
     * URL-Dekodierung inkl. %uXXXX, mehrfach bis max. 3 Runden.
     */
    public static function urlDecodeUni(string $value): string
    {
        for ($i = 0; $i < 3; $i++) {
            if (! str_contains($value, '%')) {
                break;
            }
            $decoded = (string) preg_replace_callback(
                '/%u([0-9a-fA-F]{4})/',
                static fn (array $m): string => mb_chr((int) hexdec($m[1]), 'UTF-8') ?: '',
                $value,
            );
            // rawurldecode: lässt literale „+“ unangetastet (relevant für MSSQL-Konkatenation),
            // da Laravel „+“ aus Query/Form bereits als Leerzeichen geparst hat.
            $decoded = rawurldecode($decoded);
            if ($decoded === $value) {
                break;
            }
            $value = $decoded;
        }

        return $value;
    }

    public static function htmlEntityDecode(string $value): string
    {
        if (! str_contains($value, '&')) {
            return $value;
        }
        // Entitäten ohne abschließendes Semikolon (&#60 &#x3c) ebenfalls auflösen.
        $value = (string) preg_replace_callback(
            '/&#(x[0-9a-f]+|[0-9]+);?/i',
            static function (array $m): string {
                $code = str_starts_with(strtolower($m[1]), 'x') ? hexdec(substr($m[1], 1)) : (int) $m[1];
                $code = (int) $code;

                return $code > 0 && $code < 0x110000 ? (mb_chr($code, 'UTF-8') ?: '') : '';
            },
            $value,
        );

        return html_entity_decode($value, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }

    public static function compressWhitespace(string $value): string
    {
        // Inklusive vertikaler Tabulatoren, NBSP und weiterer Unicode-Leerzeichen.
        $value = str_replace(["\xc2\xa0", "\x0b", "\x0c"], ' ', $value);

        return (string) preg_replace('/\s+/', ' ', $value);
    }

    /**
     * Entfernt SQL- (/* *\/, --, #) und HTML-Kommentare. Kommentare werden durch
     * ein Leerzeichen ersetzt, damit `UNION/**\/SELECT` zu `UNION SELECT` wird.
     */
    public static function removeComments(string $value): string
    {
        if (! preg_match('~/\*|<!--|--|#~', $value)) {
            return $value;
        }
        // MySQL-Versionskommentare /*!50000 SELECT*/ → Inhalt behalten
        $value = (string) preg_replace('~/\*!\d*~', ' ', $value);
        $value = (string) preg_replace('~/\*.*?(\*/|$)~s', ' ', $value);
        $value = (string) preg_replace('~<!--.*?(-->|$)~s', ' ', $value);
        $value = (string) preg_replace('~(--[\s\-]|--$|#)[^\n]*~', ' ', $value);

        return $value;
    }

    public static function normalizePath(string $value): string
    {
        $value = str_replace('\\', '/', $value);
        $value = (string) preg_replace('~/{2,}~', '/', $value);
        $value = (string) preg_replace('~/(\./)+~', '/', $value);

        return $value;
    }

    /**
     * NFKC-Normalisierung; Overlong-UTF-8 (z. B. %c0%ae) wird in ASCII übersetzt.
     */
    public static function utf8Normalize(string $value): string
    {
        // Overlong-Kodierungen von ASCII-Zeichen (C0/C1 xx) in das Zielzeichen übersetzen.
        $value = (string) preg_replace_callback(
            '/[\xc0\xc1][\x80-\xbf]/',
            static fn (array $m): string => chr(((ord($m[0][0]) & 0x1F) << 6) | (ord($m[0][1]) & 0x3F)),
            $value,
        );
        $value = (string) preg_replace_callback(
            '/\xe0[\x80-\x9f][\x80-\xbf]/',
            static fn (array $m): string => chr(((ord($m[0][1]) & 0x3F) << 6) | (ord($m[0][2]) & 0x3F)),
            $value,
        );

        if (class_exists(IntlNormalizer::class) && mb_check_encoding($value, 'UTF-8')) {
            $normalized = IntlNormalizer::normalize($value, IntlNormalizer::FORM_KC);
            if (is_string($normalized)) {
                return $normalized;
            }
        }

        return $value;
    }

    public static function base64DecodeIfValid(string $value): string
    {
        $trimmed = trim($value);
        if (strlen($trimmed) < 8 || strlen($trimmed) > 65536 || ! preg_match('~^[A-Za-z0-9+/_-]+={0,2}$~', $trimmed)) {
            return $value;
        }
        $decoded = base64_decode(strtr($trimmed, '-_', '+/'), true);
        if ($decoded === false || ! mb_check_encoding($decoded, 'UTF-8') || preg_match('/[\x00-\x08\x0e-\x1f]/', $decoded)) {
            return $value;
        }

        return $decoded;
    }

    public static function jsDecode(string $value): string
    {
        if (! str_contains($value, '\\')) {
            return $value;
        }
        $value = (string) preg_replace_callback(
            '/\\\\u\{?([0-9a-fA-F]{2,6})\}?|\\\\x([0-9a-fA-F]{2})|\\\\([0-7]{1,3})/',
            static function (array $m): string {
                if (($m[1] ?? '') !== '') {
                    return mb_chr((int) hexdec($m[1]), 'UTF-8') ?: '';
                }
                if (($m[2] ?? '') !== '') {
                    return chr((int) hexdec($m[2]));
                }

                return chr((int) octdec($m[3]) & 0xFF);
            },
            $value,
        );

        return (string) preg_replace('/\\\\([^\\\\])/', '$1', $value);
    }

    public static function cssDecode(string $value): string
    {
        if (! str_contains($value, '\\')) {
            return $value;
        }

        return (string) preg_replace_callback(
            '/\\\\([0-9a-fA-F]{1,6})\s?|\\\\(.)/s',
            static fn (array $m): string => ($m[1] ?? '') !== ''
                ? (mb_chr((int) hexdec($m[1]), 'UTF-8') ?: '')
                : ($m[2] === "\n" ? '' : $m[2]),
            $value,
        );
    }

    /**
     * Dekodiert 0x-präfixierte Hex-Literale (MySQL) und reine Hex-Strings.
     */
    public static function hexDecode(string $value): string
    {
        return (string) preg_replace_callback(
            '/\b0x([0-9a-fA-F]{2,})\b/',
            static function (array $m): string {
                if (strlen($m[1]) % 2 !== 0) {
                    return $m[0];
                }
                $bin = (string) hex2bin($m[1]);

                return preg_match('/^[\x20-\x7e]+$/', $bin) ? $bin : $m[0];
            },
            $value,
        );
    }

    /**
     * Normalisierung für Shell-Befehle (wie ModSecurity t:cmdLine):
     * entfernt \ ' " ^, vereinheitlicht Leerraum vor / und (, Kleinschreibung.
     */
    public static function cmdLine(string $value): string
    {
        $value = str_replace(['\\', "'", '"', '^'], '', $value);
        $value = (string) preg_replace('/\s+([\/(])/', '$1', $value);
        $value = (string) preg_replace('/[,;]+/', ' ', $value);
        $value = (string) preg_replace('/\s+/', ' ', $value);

        return strtolower($value);
    }
}
