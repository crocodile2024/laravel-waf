<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Engine;

enum Mode: string
{
    case Off = 'off';
    case Learning = 'learning';
    case Detect = 'detect';
    case Block = 'block';

    public function enforces(): bool
    {
        return $this === self::Block;
    }

    public function label(): string
    {
        return match ($this) {
            self::Off => 'Aus',
            self::Learning => 'Lernen',
            self::Detect => 'Erkennen',
            self::Block => 'Blockieren',
        };
    }

    public function badge(): string
    {
        return match ($this) {
            self::Off => 'secondary',
            self::Learning => 'info',
            self::Detect => 'warning',
            self::Block => 'success',
        };
    }

    public static function fromMixed(mixed $value, self $default = self::Detect): self
    {
        return is_string($value) ? (self::tryFrom(strtolower($value)) ?? $default) : $default;
    }

    /**
     * @return array<int, string>
     */
    public static function values(): array
    {
        return array_map(static fn (self $m) => $m->value, self::cases());
    }
}
