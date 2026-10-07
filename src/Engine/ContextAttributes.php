<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Engine;

/**
 * Anreicherungen, die Stages während der Prüfung ergänzen (Land, ASN, Profil, …).
 *
 * Bewusst vom unveränderlichen Request-Abbild getrennt.
 */
final class ContextAttributes
{
    public ?string $country = null;

    public ?int $asn = null;

    public bool $geoResolved = false;

    public bool $passCookieValid = false;

    public ?string $profile = null;

    /** @var array<int, string> */
    public array $tags = [];

    /** @var array<string, mixed> */
    public array $extra = [];
}
