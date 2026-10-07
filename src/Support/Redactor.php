<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Support;

/**
 * Schwärzt sensible Felder und kürzt Payload-Ausschnitte.
 */
final class Redactor
{
    public const MASK = '[GESCHWÄRZT]';

    /**
     * @param  array<int, string>  $keys
     */
    public function __construct(private array $keys = []) {}

    public function isSensitive(?string $name): bool
    {
        if ($name === null || $name === '') {
            return false;
        }
        $name = mb_strtolower($name);
        foreach ($this->keys as $key) {
            $key = mb_strtolower($key);
            if ($key !== '' && str_contains($name, $key)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Liefert einen geschwärzten, gekürzten Ausschnitt um die Trefferstelle.
     */
    public function snippet(?string $parameter, string $value, ?int $offset = null, int $max = 512): string
    {
        if ($this->isSensitive($parameter)) {
            return self::MASK;
        }

        $value = self::toValidUtf8($value);
        if (mb_strlen($value) <= $max) {
            return $value;
        }

        $offset = $offset !== null ? mb_strlen(substr($value, 0, max(0, $offset))) : 0;
        $start = max(0, $offset - intdiv($max, 2));
        $start = min($start, mb_strlen($value) - $max);

        return ($start > 0 ? '…' : '').mb_substr($value, $start, $max).($start + $max < mb_strlen($value) ? '…' : '');
    }

    /**
     * Schwärzt sensible Schlüssel in einem flachen oder verschachtelten Array.
     *
     * @param  array<array-key, mixed>  $data
     * @return array<array-key, mixed>
     */
    public function redactArray(array $data): array
    {
        foreach ($data as $key => $value) {
            if ($this->isSensitive((string) $key)) {
                $data[$key] = self::MASK;
            } elseif (is_array($value)) {
                $data[$key] = $this->redactArray($value);
            }
        }

        return $data;
    }

    public static function toValidUtf8(string $value): string
    {
        if (mb_check_encoding($value, 'UTF-8')) {
            return $value;
        }

        return mb_convert_encoding($value, 'UTF-8', 'UTF-8');
    }
}
