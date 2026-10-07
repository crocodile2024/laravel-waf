<?php

declare(strict_types=1);

use Crocodile2024\WAF\Engine\Rules\RuleCompiler;
use Crocodile2024\WAF\Engine\Rules\RuleValidationException;

function validRule(array $overrides = []): array
{
    return array_merge([
        'code' => 'WAF-TEST-001',
        'name' => 'Test',
        'severity' => 'critical',
        'paranoia_level' => 1,
        'priority' => 100,
        'phase' => 'request',
        'tags' => ['test'],
        'transforms' => ['lowercase'],
        'conditions' => ['match' => 'any', 'items' => [['target' => 'query.q', 'operator' => 'contains', 'value' => 'evil']]],
        'action' => ['type' => 'block', 'status' => 403],
    ], $overrides);
}

test('compiles a valid rule', function () {
    $compiled = (new RuleCompiler)->compile(validRule());
    expect($compiled['code'])->toBe('WAF-TEST-001')
        ->and($compiled['points'])->toBe(5)
        ->and($compiled['action']['type'])->toBe('block');
});

test('rejects invalid severity', function () {
    expect(fn () => (new RuleCompiler)->compile(validRule(['severity' => 'fatal'])))
        ->toThrow(RuleValidationException::class);
});

test('rejects ReDoS regex in conditions', function () {
    $rule = validRule(['conditions' => ['match' => 'any', 'items' => [['target' => 'query.q', 'operator' => 'regex', 'value' => '(a+)+']]]]);
    expect(fn () => (new RuleCompiler)->compile($rule))->toThrow(RuleValidationException::class);
});

test('rejects invalid block status', function () {
    expect(fn () => (new RuleCompiler)->compile(validRule(['action' => ['type' => 'block', 'status' => 418]]))
    )->toThrow(RuleValidationException::class);
});

test('rejects nested groups deeper than one level', function () {
    $rule = validRule(['conditions' => ['match' => 'all', 'items' => [
        ['match' => 'any', 'items' => [['match' => 'any', 'items' => [['target' => 'query.q', 'operator' => 'exists']]]]],
    ]]]);
    expect(fn () => (new RuleCompiler)->compile($rule))->toThrow(RuleValidationException::class);
});

test('validates ip_in_cidr values', function () {
    $rule = validRule(['conditions' => ['match' => 'any', 'items' => [['target' => 'ip', 'operator' => 'ip_in_cidr', 'value' => ['999.0.0.0/8']]]]]);
    expect((new RuleCompiler)->validate($rule))->not->toBe([]);
});
