<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Engine\Rules;

use Crocodile2024\WAF\Engine\Detectors\SqliDetector;
use Crocodile2024\WAF\Engine\Detectors\XssDetector;
use Crocodile2024\WAF\Engine\Normalizer\Transformer;
use Crocodile2024\WAF\Engine\RequestContext;
use Crocodile2024\WAF\Support\IpSet;

/**
 * Wertet kompilierte Regeln gegen einen RequestContext aus.
 *
 * Pro Instanz (= pro Request) werden Transformationen zwischengespeichert.
 */
final class RuleMatcher
{
    private const MAX_MATCHES_PER_ITEM = 5;

    /** @var array<string, array<int, array{0: string|null, 1: string}>> */
    private array $targetCache = [];

    /** @var array<string, IpSet> */
    private array $ipSets = [];

    public function __construct(
        private readonly RequestContext $ctx,
        private readonly Transformer $transformer = new Transformer,
        private readonly SqliDetector $sqli = new SqliDetector,
        private readonly XssDetector $xss = new XssDetector,
        private readonly ?\Closure $tracer = null,
    ) {}

    /**
     * @param  array<string, mixed>  $rule  kompilierte Regel
     * @return array<int, RuleMatch>
     */
    public function match(array $rule, bool $enforced = true): array
    {
        $hits = $this->evaluateGroup($rule['conditions'], $rule['transforms']);
        if ($hits === null) {
            return [];
        }
        if ($hits === []) {
            $hits = [['target' => 'request', 'parameter' => null, 'value' => '', 'offset' => null, 'transforms' => []]];
        }

        $out = [];
        foreach ($hits as $hit) {
            $out[] = new RuleMatch(
                ruleCode: $rule['code'],
                ruleName: $rule['name'],
                severity: $rule['severity'],
                points: $rule['points'],
                target: $hit['target'],
                parameter: $hit['parameter'],
                value: $hit['value'],
                offset: $hit['offset'],
                tags: $rule['tags'],
                transforms: $hit['transforms'],
                enforced: $enforced,
            );
        }

        return $out;
    }

    /**
     * @param  array<string, mixed>  $group
     * @param  array<int, string>  $transforms
     * @return array<int, array{target: string, parameter: string|null, value: string, offset: int|null, transforms: array<int, string>}>|null
     */
    private function evaluateGroup(array $group, array $transforms): ?array
    {
        $all = $group['match'] === 'all';
        $collected = [];

        foreach ($group['items'] as $item) {
            $result = isset($item['items'])
                ? $this->evaluateGroup($item, $transforms)
                : $this->evaluateItem($item, $item['transforms'] ?? $transforms);

            if ($all) {
                if ($result === null) {
                    return null;
                }
                array_push($collected, ...$result);
            } elseif ($result !== null) {
                return $result;
            }
        }

        return $all ? $collected : null;
    }

    /**
     * @param  array<string, mixed>  $item
     * @param  array<int, string>  $transforms
     * @return array<int, array{target: string, parameter: string|null, value: string, offset: int|null, transforms: array<int, string>}>|null
     */
    private function evaluateItem(array $item, array $transforms): ?array
    {
        $target = $item['target'];
        $values = $this->targetCache[$target] ??= TargetResolver::values($this->ctx, $target);
        $op = $item['operator'];
        $negate = $item['negate'];

        if ($op === 'exists' || $op === 'not_exists') {
            $present = $values !== [];
            $ok = ($op === 'exists') === $present;
            if ($negate) {
                $ok = ! $ok;
            }
            if (! $ok) {
                return null;
            }

            return $present && ! $negate && $op === 'exists'
                ? [['target' => $target, 'parameter' => $values[0][0], 'value' => $values[0][1], 'offset' => null, 'transforms' => []]]
                : [['target' => $target, 'parameter' => null, 'value' => '', 'offset' => null, 'transforms' => []]];
        }

        $hits = [];
        foreach ($values as [$param, $raw]) {
            $value = in_array($op, ['ip_in_cidr', 'gt', 'lt'], true) ? $raw : $this->transformer->apply($raw, $transforms);
            $offset = null;
            if ($this->test($op, $item['value'], $value, $offset)) {
                if ($negate) {
                    return null;
                }
                $hits[] = [
                    'target' => $target,
                    'parameter' => $param,
                    'value' => $raw,
                    'offset' => $offset !== null && $value === $raw ? $offset : null,
                    'transforms' => $transforms,
                ];
                if ($this->tracer !== null) {
                    ($this->tracer)($target, $param, $raw, $value, $transforms);
                }
                if (count($hits) >= self::MAX_MATCHES_PER_ITEM) {
                    break;
                }
            }
        }

        if ($negate) {
            return [['target' => $target, 'parameter' => null, 'value' => '', 'offset' => null, 'transforms' => []]];
        }

        return $hits === [] ? null : $hits;
    }

    private function test(string $op, mixed $expected, string $value, ?int &$offset): bool
    {
        switch ($op) {
            case 'regex':
                return RegexGuard::match((string) $expected, $value, $offset);
            case 'contains':
                $pos = strpos($value, (string) $expected);
                if ($pos === false) {
                    return false;
                }
                $offset = $pos;

                return true;
            case 'equals':
                return $value === (string) $expected;
            case 'starts_with':
                return str_starts_with($value, (string) $expected);
            case 'ends_with':
                return str_ends_with($value, (string) $expected);
            case 'in_list':
                return isset($expected[$value]);
            case 'ip_in_cidr':
                $key = md5(serialize($expected));
                $set = $this->ipSets[$key] ??= IpSet::fromArray((array) $expected);

                return $set->contains($value);
            case 'gt':
                return is_numeric($value) && (float) $value > (float) $expected;
            case 'lt':
                return is_numeric($value) && (float) $value < (float) $expected;
            case 'length_gt':
                return strlen($value) > (float) $expected;
            case 'detect_sqli':
                return $this->sqli->detect($value) !== null;
            case 'detect_xss':
                return $this->xss->detect($value) !== null;
        }

        return false;
    }

    public function transformer(): Transformer
    {
        return $this->transformer;
    }
}
