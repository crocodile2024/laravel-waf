<?php

declare(strict_types=1);

use Crocodile2024\WAF\Engine\Normalizer\Transformer;

test('url decode handles multiple rounds and %u', function () {
    $t = new Transformer;
    expect($t->apply('%2527', ['urlDecodeUni']))->toBe("'")
        ->and($t->apply('%u003cscript', ['urlDecodeUni']))->toBe('<script')
        ->and($t->apply('a%2Bb', ['urlDecodeUni']))->toBe('a+b');
});

test('literal plus is preserved', function () {
    $t = new Transformer;
    expect($t->apply("' + CHAR(65)", ['urlDecodeUni']))->toBe("' + CHAR(65)");
});

test('remove comments merges sql tokens', function () {
    $t = new Transformer;
    expect($t->apply('UNION/**/SELECT', ['removeComments', 'compressWhitespace']))->toBe('UNION SELECT')
        ->and($t->apply('1/*!50000UNION*/2', ['removeComments', 'compressWhitespace']))->toContain('UNION');
});

test('html entity decode without semicolon', function () {
    $t = new Transformer;
    expect($t->apply('&#60;&#x3e;', ['htmlEntityDecode']))->toBe('<>');
});

test('overlong utf8 is normalised', function () {
    $t = new Transformer;
    expect($t->apply("%c0%ae%c0%ae", ['urlDecodeUni', 'utf8Normalize']))->toBe('..');
});

test('base64 decode only when valid', function () {
    $t = new Transformer;
    expect($t->apply('PHNjcmlwdD4=', ['base64DecodeIfValid']))->toBe('<script>')
        ->and($t->apply('hallo welt', ['base64DecodeIfValid']))->toBe('hallo welt');
});

test('path normalisation', function () {
    $t = new Transformer;
    expect($t->apply('a\\\\b//c/./d', ['normalizePath']))->toBe('a/b/c/d');
});

test('transformer is deterministic and cached', function () {
    $t = new Transformer;
    $chain = ['urlDecodeUni', 'lowercase'];
    expect($t->apply('%41BC', $chain))->toBe('abc')
        ->and($t->apply('%41BC', $chain))->toBe('abc');
});
