<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Engine\Detectors;

interface Detector
{
    /**
     * Liefert einen Fingerprint/Grund bei Erkennung, sonst null.
     */
    public function detect(string $value): ?string;
}
