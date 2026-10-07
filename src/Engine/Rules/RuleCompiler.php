<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Engine\Rules;

use Crocodile2024\WAF\Engine\Mode;
use Crocodile2024\WAF\Engine\Normalizer\Transformer;
use Crocodile2024\WAF\Engine\Scoring\Severity;
use Crocodile2024\WAF\Support\IpMatcher;
use Crocodile2024\WAF\Support\IpSet;

/**
 * Validiert Regeln (Anhang A) und kompiliert sie in einen schnell auswertbaren Array-Plan.
 */
final class RuleCompiler
{
    public const OPERATORS = [
        'equals', 'contains', 'starts_with', 'ends_with', 'regex', 'in_list', 'ip_in_cidr',
        'gt', 'lt', 'exists', 'not_exists', 'length_gt', 'detect_sqli', 'detect_xss',
    ];

    public const ACTIONS = ['score', 'block', 'allow', 'challenge', 'log', 'ban', 'rate_limit', 'tag'];

    public const BLOCK_STATUSES = [403, 404, 429, 503];

    /**
     * Prüft eine Regeldefinition und liefert alle Fehler (deutsch).
     *
     * @param  array<string, mixed>  $rule
     * @return array<int, string>
     */
    public function validate(array $rule): array
    {
        $errors = [];

        $code = $rule['code'] ?? null;
        if (! is_string($code) || ! preg_match('/^[A-Z0-9][A-Z0-9_\-]{2,63}$/', $code)) {
            $errors[] = 'Der Regelcode muss aus 3–64 Großbuchstaben, Ziffern, „-“ oder „_“ bestehen.';
        }
        if (! is_string($rule['name'] ?? null) || trim((string) $rule['name']) === '') {
            $errors[] = 'Der Name ist erforderlich.';
        }
        if (! in_array($rule['severity'] ?? null, Severity::values(), true)) {
            $errors[] = 'Ungültige Schwere (erlaubt: '.implode(', ', Severity::values()).').';
        }
        $pl = $rule['paranoia_level'] ?? 1;
        if (! is_int($pl) || $pl < 1 || $pl > 4) {
            $errors[] = 'Das Paranoia-Level muss zwischen 1 und 4 liegen.';
        }
        $priority = $rule['priority'] ?? 500;
        if (! is_int($priority) || $priority < 0 || $priority > 1000) {
            $errors[] = 'Die Priorität muss zwischen 0 und 1000 liegen.';
        }
        if (! in_array($rule['phase'] ?? 'request', ['request', 'response'], true)) {
            $errors[] = 'Die Phase muss „request“ oder „response“ sein.';
        }
        if (isset($rule['mode_override']) && $rule['mode_override'] !== null && ! in_array($rule['mode_override'], Mode::values(), true)) {
            $errors[] = 'Ungültiger Modus-Override.';
        }
        foreach ((array) ($rule['transforms'] ?? []) as $t) {
            if (! is_string($t) || ! Transformer::isValid($t)) {
                $errors[] = 'Unbekannte Transformation: '.(is_string($t) ? $t : json_encode($t)).'.';
            }
        }
        if (! is_array($rule['tags'] ?? [])) {
            $errors[] = 'Tags müssen eine Liste sein.';
        }

        $conditions = $rule['conditions'] ?? null;
        if (! is_array($conditions)) {
            $errors[] = 'Bedingungen fehlen.';
        } else {
            $errors = [...$errors, ...$this->validateGroup($conditions, 0)];
        }

        $errors = [...$errors, ...$this->validateAction($rule['action'] ?? null)];

        return $errors;
    }

    /**
     * @param  array<string, mixed>  $group
     * @return array<int, string>
     */
    private function validateGroup(array $group, int $depth): array
    {
        $errors = [];
        if (! in_array($group['match'] ?? null, ['all', 'any'], true)) {
            $errors[] = 'Die Verknüpfung muss „all“ (UND) oder „any“ (ODER) sein.';
        }
        $items = $group['items'] ?? null;
        if (! is_array($items) || $items === []) {
            return [...$errors, 'Mindestens eine Bedingung ist erforderlich.'];
        }
        if (count($items) > 50) {
            $errors[] = 'Höchstens 50 Bedingungen pro Gruppe.';
        }

        foreach ($items as $i => $item) {
            $n = $i + 1;
            if (! is_array($item)) {
                $errors[] = "Bedingung {$n} ist ungültig.";

                continue;
            }
            if (isset($item['items'])) {
                if ($depth >= 1) {
                    $errors[] = 'Bedingungsgruppen dürfen nur eine Ebene tief verschachtelt werden.';

                    continue;
                }
                $errors = [...$errors, ...$this->validateGroup($item, $depth + 1)];

                continue;
            }
            $target = $item['target'] ?? null;
            if (! is_string($target) || ! TargetResolver::isValid($target)) {
                $errors[] = "Bedingung {$n}: unbekanntes Ziel „".(is_string($target) ? $target : '').'“.';
            }
            $op = $item['operator'] ?? null;
            if (! in_array($op, self::OPERATORS, true)) {
                $errors[] = "Bedingung {$n}: unbekannter Operator „".(is_string($op) ? $op : '').'“.';

                continue;
            }
            foreach ((array) ($item['transforms'] ?? []) as $t) {
                if (! is_string($t) || ! Transformer::isValid($t)) {
                    $errors[] = "Bedingung {$n}: unbekannte Transformation.";
                }
            }
            $value = $item['value'] ?? null;
            switch ($op) {
                case 'regex':
                    $msg = is_string($value) ? RegexGuard::validate($value) : 'Der reguläre Ausdruck fehlt.';
                    if ($msg !== null) {
                        $errors[] = "Bedingung {$n}: {$msg}";
                    }
                    break;
                case 'gt':
                case 'lt':
                case 'length_gt':
                    if (! is_numeric($value)) {
                        $errors[] = "Bedingung {$n}: Der Vergleichswert muss eine Zahl sein.";
                    }
                    break;
                case 'in_list':
                    if ($this->listValue($value) === []) {
                        $errors[] = "Bedingung {$n}: Die Liste darf nicht leer sein.";
                    }
                    break;
                case 'ip_in_cidr':
                    $list = $this->listValue($value);
                    if ($list === []) {
                        $errors[] = "Bedingung {$n}: Mindestens ein CIDR ist erforderlich.";
                    }
                    foreach ($list as $cidr) {
                        if (! IpMatcher::isValidCidr($cidr)) {
                            $errors[] = "Bedingung {$n}: „{$cidr}“ ist keine gültige IP/CIDR.";
                        }
                    }
                    break;
                case 'exists':
                case 'not_exists':
                case 'detect_sqli':
                case 'detect_xss':
                    break;
                default:
                    if (! is_scalar($value) || (string) $value === '') {
                        $errors[] = "Bedingung {$n}: Ein Vergleichswert ist erforderlich.";
                    }
            }
        }

        return $errors;
    }

    /**
     * @return array<int, string>
     */
    private function validateAction(mixed $action): array
    {
        if (! is_array($action) || ! in_array($action['type'] ?? null, self::ACTIONS, true)) {
            return ['Ungültige oder fehlende Aktion.'];
        }
        $errors = [];
        switch ($action['type']) {
            case 'block':
                if (isset($action['status']) && ! in_array((int) $action['status'], self::BLOCK_STATUSES, true)) {
                    $errors[] = 'Statuscode muss 403, 404, 429 oder 503 sein.';
                }
                break;
            case 'ban':
                if (isset($action['minutes']) && (! is_numeric($action['minutes']) || (int) $action['minutes'] < 1)) {
                    $errors[] = 'Die Sperrdauer muss mindestens 1 Minute betragen.';
                }
                break;
            case 'rate_limit':
                if (! is_string($action['profile'] ?? null) || $action['profile'] === '') {
                    $errors[] = 'Für „rate_limit“ muss ein Profil angegeben werden.';
                }
                break;
            case 'tag':
                if (! is_string($action['tag'] ?? null) || $action['tag'] === '') {
                    $errors[] = 'Für „tag“ muss ein Tag-Name angegeben werden.';
                }
                break;
            case 'score':
                if (isset($action['points']) && ! is_numeric($action['points'])) {
                    $errors[] = 'Punkte müssen eine Zahl sein.';
                }
                break;
        }

        return $errors;
    }

    /**
     * Kompiliert eine (validierte) Regel.
     *
     * @param  array<string, mixed>  $rule
     * @return array<string, mixed>
     */
    public function compile(array $rule): array
    {
        $errors = $this->validate($rule);
        if ($errors !== []) {
            throw new RuleValidationException($errors, is_string($rule['code'] ?? null) ? $rule['code'] : null);
        }

        $severity = Severity::from((string) $rule['severity']);
        $action = (array) $rule['action'];
        $points = isset($action['points']) ? (int) $action['points'] : $severity->score();

        return [
            'code' => (string) $rule['code'],
            'name' => (string) $rule['name'],
            'severity' => $severity->value,
            'points' => $points,
            'pl' => (int) ($rule['paranoia_level'] ?? 1),
            'priority' => (int) ($rule['priority'] ?? 500),
            'phase' => (string) ($rule['phase'] ?? 'request'),
            'tags' => array_values(array_map('strval', (array) ($rule['tags'] ?? []))),
            'transforms' => array_values((array) ($rule['transforms'] ?? [])),
            'mode' => $rule['mode_override'] ?? null,
            'action' => $action,
            'conditions' => $this->compileGroup((array) $rule['conditions']),
        ];
    }

    /**
     * @param  array<string, mixed>  $group
     * @return array<string, mixed>
     */
    private function compileGroup(array $group): array
    {
        $items = [];
        foreach ((array) $group['items'] as $item) {
            $item = (array) $item;
            if (isset($item['items'])) {
                $items[] = $this->compileGroup($item);

                continue;
            }
            $op = (string) $item['operator'];
            $value = $item['value'] ?? null;
            $compiled = match ($op) {
                'regex' => RegexGuard::compile((string) $value),
                'in_list' => array_fill_keys($this->listValue($value), true),
                'ip_in_cidr' => IpSet::fromEntries(array_map(static fn (string $c) => ['cidr' => $c], $this->listValue($value)))->toArray(),
                'gt', 'lt', 'length_gt' => (float) $value,
                'exists', 'not_exists', 'detect_sqli', 'detect_xss' => null,
                default => (string) $value,
            };
            $items[] = [
                'target' => (string) $item['target'],
                'operator' => $op,
                'value' => $compiled,
                'negate' => (bool) ($item['negate'] ?? false),
                'transforms' => isset($item['transforms']) ? array_values((array) $item['transforms']) : null,
            ];
        }

        return ['match' => (string) $group['match'], 'items' => $items];
    }

    /**
     * @return array<int, string>
     */
    private function listValue(mixed $value): array
    {
        if (is_string($value)) {
            $value = preg_split('/[\r\n,]+/', $value) ?: [];
        }
        if (! is_array($value)) {
            return [];
        }

        return array_values(array_filter(array_map(static fn ($v) => trim((string) $v), $value), static fn (string $v) => $v !== ''));
    }
}
