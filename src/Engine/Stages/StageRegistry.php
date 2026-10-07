<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Engine\Stages;

use Closure;

/**
 * Registrierung zusätzlicher Inspection-Stages (WAF::extend()).
 *
 * Als Singleton gebunden, damit die Host-App im Boot Stages anmelden kann und
 * die Engine sie pro Request abruft.
 */
class StageRegistry
{
    /** @var array<string, Closure():InspectionStage|InspectionStage> */
    private array $stages = [];

    public function register(string $name, Closure|InspectionStage $stage): void
    {
        $this->stages[$name] = $stage;
    }

    /**
     * @return array<int, InspectionStage>
     */
    public function all(): array
    {
        $resolved = [];
        foreach ($this->stages as $stage) {
            $resolved[] = $stage instanceof Closure ? $stage() : $stage;
        }

        return $resolved;
    }

    public function clear(): void
    {
        $this->stages = [];
    }
}
