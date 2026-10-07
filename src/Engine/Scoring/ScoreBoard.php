<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Engine\Scoring;

/**
 * Summiert Anomalie-Punkte eines Requests mit Aufschlüsselung.
 */
final class ScoreBoard
{
    private int $total = 0;

    /** @var array<string, int> */
    private array $breakdown = [];

    public function add(string $source, int $points): void
    {
        if ($points === 0) {
            return;
        }
        $this->total += $points;
        $this->breakdown[$source] = ($this->breakdown[$source] ?? 0) + $points;
    }

    public function total(): int
    {
        return $this->total;
    }

    /**
     * @return array<string, int>
     */
    public function breakdown(): array
    {
        return $this->breakdown;
    }

    public function exceeds(int $threshold): bool
    {
        return $threshold > 0 && $this->total >= $threshold;
    }
}
