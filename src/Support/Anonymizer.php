<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Support;

/**
 * IP-Anonymisierung und -Pseudonymisierung (DSGVO).
 */
final class Anonymizer
{
    /**
     * IPv4 → letztes Oktett 0, IPv6 → /48.
     */
    public static function anonymize(string $ip): string
    {
        $bin = IpMatcher::isValidIp($ip) ? inet_pton($ip) : false;
        if ($bin === false) {
            return '';
        }
        [$start] = IpMatcher::range($bin, strlen($bin) === 4 ? 24 : 48);

        return (string) inet_ntop($start);
    }

    public static function hash(string $ip, string $pepper): string
    {
        return hash_hmac('sha256', $ip, $pepper);
    }

    public static function hashIdentifier(string $value, string $pepper): string
    {
        return hash_hmac('sha256', 'id:'.mb_strtolower(trim($value)), $pepper);
    }
}
