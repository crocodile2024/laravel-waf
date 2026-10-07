<?php

declare(strict_types=1);

use Crocodile2024\WAF\Engine\Rules\RegexGuard;

test('rejects nested quantifiers (ReDoS)', function () {
    expect(RegexGuard::validate('(a+)+'))->not->toBeNull()
        ->and(RegexGuard::validate('(a*)*'))->not->toBeNull()
        ->and(RegexGuard::validate('(a+)+$'))->not->toBeNull()
        ->and(RegexGuard::validate('([a-z]+)*'))->not->toBeNull()
        ->and(RegexGuard::validate('(\\d{1,100}){1,100}'))->not->toBeNull();
});

test('accepts safe patterns', function () {
    expect(RegexGuard::validate('\\bunion\\b\\s+select'))->toBeNull()
        ->and(RegexGuard::validate('[a-z]+@[a-z]+'))->toBeNull()
        ->and(RegexGuard::validate('(foo|bar)+'))->toBeNull();
});

test('rejects empty and invalid', function () {
    expect(RegexGuard::validate(''))->not->toBeNull()
        ->and(RegexGuard::validate('(unclosed'))->not->toBeNull();
});

test('match returns offset', function () {
    $offset = null;
    $hit = RegexGuard::match(RegexGuard::compile('select'), 'abc select def', $offset);
    expect($hit)->toBeTrue()->and($offset)->toBe(4);
});
