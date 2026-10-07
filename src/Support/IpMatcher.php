<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Support;

/**
 * IP- und CIDR-Hilfsfunktionen für IPv4 und IPv6.
 *
 * Bereiche werden als binäre Start-/Endadressen (inet_pton) dargestellt,
 * damit sie per strcmp verglichen werden können.
 */
final class IpMatcher
{
    public static function isValidIp(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP) !== false;
    }

    public static function isValidCidr(string $cidr): bool
    {
        return self::parse($cidr) !== null;
    }

    public static function isIpv6(string $ip): bool
    {
        return str_contains($ip, ':');
    }

    /**
     * Zerlegt eine IP oder ein CIDR in normalisierte Form und Binärbereich.
     *
     * @return array{cidr: string, start: string, end: string, version: int}|null
     */
    public static function parse(string $cidr): ?array
    {
        $cidr = trim($cidr);
        if ($cidr === '') {
            return null;
        }

        $parts = explode('/', $cidr, 2);
        $ip = $parts[0];
        if (! self::isValidIp($ip)) {
            return null;
        }

        $bin = inet_pton($ip);
        if ($bin === false) {
            return null;
        }

        $bits = strlen($bin) * 8;
        $prefix = $bits;
        if (isset($parts[1])) {
            if (! ctype_digit($parts[1])) {
                return null;
            }
            $prefix = (int) $parts[1];
            if ($prefix < 0 || $prefix > $bits) {
                return null;
            }
        }

        [$start, $end] = self::range($bin, $prefix);
        $network = (string) inet_ntop($start);

        return [
            'cidr' => $prefix === $bits ? $network : $network.'/'.$prefix,
            'start' => $start,
            'end' => $end,
            'version' => $bits === 32 ? 4 : 6,
        ];
    }

    /**
     * @return array{0: string, 1: string}
     */
    public static function range(string $bin, int $prefix): array
    {
        $len = strlen($bin);
        $start = '';
        $end = '';
        for ($i = 0; $i < $len; $i++) {
            $bitsInByte = max(0, min(8, $prefix - $i * 8));
            $mask = $bitsInByte === 0 ? 0 : (0xFF << (8 - $bitsInByte)) & 0xFF;
            $byte = ord($bin[$i]);
            $start .= chr($byte & $mask);
            $end .= chr(($byte & $mask) | (~$mask & 0xFF));
        }

        return [$start, $end];
    }

    public static function contains(string $cidr, string $ip): bool
    {
        $range = self::parse($cidr);
        $bin = self::isValidIp($ip) ? inet_pton($ip) : false;
        if ($range === null || $bin === false || strlen($bin) !== strlen($range['start'])) {
            return false;
        }

        return strcmp($bin, $range['start']) >= 0 && strcmp($bin, $range['end']) <= 0;
    }

    /**
     * Schlüssel für Rate-Limits und Bans: IPv4 unverändert, IPv6 auf Präfix aggregiert.
     */
    public static function key(string $ip, int $ipv6Prefix = 64): string
    {
        if (! self::isIpv6($ip)) {
            return $ip;
        }

        $bin = @inet_pton($ip);
        if ($bin === false || strlen($bin) !== 16) {
            return $ip;
        }

        [$start] = self::range($bin, $ipv6Prefix);

        return inet_ntop($start).'/'.$ipv6Prefix;
    }

    /**
     * Zählt, wie viele Adressen ein CIDR umfasst (gekappt bei PHP_INT_MAX).
     */
    public static function prefixLength(string $cidr): int
    {
        $parsed = self::parse($cidr);
        if ($parsed === null) {
            return 0;
        }
        $parts = explode('/', $parsed['cidr']);

        return isset($parts[1]) ? (int) $parts[1] : ($parsed['version'] === 4 ? 32 : 128);
    }

    public static function isPrivateOrReserved(string $ip): bool
    {
        return self::isValidIp($ip)
            && filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false;
    }
}
