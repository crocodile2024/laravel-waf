<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Engine\Scoring;

enum Severity: string
{
    case Critical = 'critical';
    case Error = 'error';
    case Warning = 'warning';
    case Notice = 'notice';

    public function score(): int
    {
        return match ($this) {
            self::Critical => 5,
            self::Error => 4,
            self::Warning => 3,
            self::Notice => 2,
        };
    }

    public function label(): string
    {
        return match ($this) {
            self::Critical => 'Kritisch',
            self::Error => 'Fehler',
            self::Warning => 'Warnung',
            self::Notice => 'Hinweis',
        };
    }

    public function rank(): int
    {
        return $this->score();
    }

    /**
     * @return array<int, string>
     */
    public static function values(): array
    {
        return array_map(static fn (self $s) => $s->value, self::cases());
    }
}
