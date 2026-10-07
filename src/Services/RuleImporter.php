<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Services;

use Crocodile2024\WAF\Engine\Rules\RuleCompiler;
use Crocodile2024\WAF\Engine\Rules\RuleValidationException;
use Crocodile2024\WAF\Models\Rule;
use Illuminate\Support\Facades\DB;
use JsonException;
use RuntimeException;

/**
 * Importiert Regelpakete (Anhang A) mit Schema-Validierung.
 */
class RuleImporter
{
    public function __construct(
        private readonly RuleCompiler $compiler,
    ) {}

    public function corePackPath(): string
    {
        return __DIR__.'/../../resources/rules/core-v1.json';
    }

    public function importCorePack(): int
    {
        return $this->importFile($this->corePackPath(), 'core');
    }

    public function importFile(string $path, ?string $sourceOverride = null): int
    {
        if (! is_file($path)) {
            throw new RuntimeException("Regelpaket nicht gefunden: {$path}");
        }

        return $this->import((string) file_get_contents($path), $sourceOverride);
    }

    /**
     * @return int Anzahl importierter/aktualisierter Regeln
     */
    public function import(string $json, ?string $sourceOverride = null): int
    {
        try {
            $pack = json_decode($json, true, 64, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new RuntimeException('Ungültiges JSON: '.$e->getMessage());
        }

        $this->validateSchema($pack);

        $source = $sourceOverride ?? 'import';
        $packName = $pack['pack'] ?? null;
        $version = $pack['version'] ?? null;

        $count = 0;
        DB::transaction(function () use ($pack, $source, $packName, $version, &$count): void {
            foreach ($pack['rules'] as $i => $definition) {
                $errors = $this->compiler->validate($definition);
                if ($errors !== []) {
                    throw new RuleValidationException($errors, $definition['code'] ?? ('#'.$i));
                }
                Rule::query()->updateOrCreate(
                    ['code' => $definition['code']],
                    [
                        'source' => $source,
                        'pack' => $packName,
                        'pack_version' => $version,
                        'name' => $definition['name'],
                        'description' => $definition['description'] ?? null,
                        'severity' => $definition['severity'],
                        'paranoia_level' => $definition['paranoia_level'] ?? 1,
                        'priority' => $definition['priority'] ?? 500,
                        'phase' => $definition['phase'] ?? 'request',
                        'conditions' => $definition['conditions'],
                        'transforms' => $definition['transforms'] ?? [],
                        'action' => $definition['action'],
                        'mode_override' => $definition['mode_override'] ?? null,
                        'tags' => $definition['tags'] ?? [],
                        'is_active' => true,
                    ],
                );
                $count++;
            }
        });

        return $count;
    }

    /**
     * @param  mixed  $pack
     */
    private function validateSchema($pack): void
    {
        if (! is_array($pack)) {
            throw new RuntimeException('Das Regelpaket muss ein JSON-Objekt sein.');
        }
        if (($pack['schema'] ?? null) !== 'waf-rulepack/1') {
            throw new RuntimeException('Unbekanntes Schema. Erwartet: „waf-rulepack/1“.');
        }
        if (! isset($pack['rules']) || ! is_array($pack['rules'])) {
            throw new RuntimeException('Das Feld „rules“ fehlt oder ist ungültig.');
        }
        $allowedTop = ['schema', 'pack', 'version', 'description', 'rules'];
        foreach (array_keys($pack) as $key) {
            if (! in_array($key, $allowedTop, true)) {
                throw new RuntimeException("Unbekanntes Feld im Regelpaket: „{$key}“.");
            }
        }
    }
}
