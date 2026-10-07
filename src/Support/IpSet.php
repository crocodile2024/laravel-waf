<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Support;

/**
 * Kompilierte Menge von IP-Bereichen mit schneller Mitgliedschaftsprüfung.
 *
 * Bereiche werden nach Startadresse sortiert und bei Abfrage binär durchsucht.
 * Serialisierbar als Array (für Redis/APCu).
 */
final class IpSet
{
    /**
     * @param  array<int, array{0: string, 1: string, 2: string}>  $v4  [start, end, id]
     * @param  array<int, array{0: string, 1: string, 2: string}>  $v6
     */
    public function __construct(
        private array $v4 = [],
        private array $v6 = [],
    ) {}

    /**
     * @param  iterable<array{cidr: string, id?: string|null}>  $entries
     */
    public static function fromEntries(iterable $entries): self
    {
        $v4 = [];
        $v6 = [];
        foreach ($entries as $entry) {
            $parsed = IpMatcher::parse($entry['cidr']);
            if ($parsed === null) {
                continue;
            }
            $row = [$parsed['start'], $parsed['end'], (string) ($entry['id'] ?? $parsed['cidr'])];
            if ($parsed['version'] === 4) {
                $v4[] = $row;
            } else {
                $v6[] = $row;
            }
        }

        $sort = static fn (array $a, array $b): int => strcmp($a[0], $b[0]);
        usort($v4, $sort);
        usort($v6, $sort);

        return new self($v4, $v6);
    }

    public function isEmpty(): bool
    {
        return $this->v4 === [] && $this->v6 === [];
    }

    public function contains(string $ip): bool
    {
        return $this->match($ip) !== null;
    }

    /**
     * Liefert die ID des ersten passenden Eintrags oder null.
     */
    public function match(string $ip): ?string
    {
        if ($this->isEmpty() || ! IpMatcher::isValidIp($ip)) {
            return null;
        }
        $bin = inet_pton($ip);
        if ($bin === false) {
            return null;
        }
        $list = strlen($bin) === 4 ? $this->v4 : $this->v6;

        // Bereiche können sich überlappen; daher alle Kandidaten mit start <= ip prüfen,
        // beginnend beim letzten passenden Start (binäre Suche).
        $lo = 0;
        $hi = count($list) - 1;
        $pos = -1;
        while ($lo <= $hi) {
            $mid = intdiv($lo + $hi, 2);
            if (strcmp($list[$mid][0], $bin) <= 0) {
                $pos = $mid;
                $lo = $mid + 1;
            } else {
                $hi = $mid - 1;
            }
        }
        for ($i = $pos; $i >= 0; $i--) {
            if (strcmp($bin, $list[$i][1]) <= 0) {
                return $list[$i][2];
            }
        }

        return null;
    }

    /**
     * @return array{v4: array<int, array{0: string, 1: string, 2: string}>, v6: array<int, array{0: string, 1: string, 2: string}>}
     */
    public function toArray(): array
    {
        return ['v4' => $this->v4, 'v6' => $this->v6];
    }

    /**
     * @param  array{v4?: array<int, array{0: string, 1: string, 2: string}>, v6?: array<int, array{0: string, 1: string, 2: string}>}  $data
     */
    public static function fromArray(array $data): self
    {
        return new self($data['v4'] ?? [], $data['v6'] ?? []);
    }
}
