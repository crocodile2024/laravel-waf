<?php

declare(strict_types=1);

use Crocodile2024\WAF\Support\IpMatcher;
use Crocodile2024\WAF\Support\IpSet;

test('cidr contains ipv4', function () {
    expect(IpMatcher::contains('192.168.0.0/24', '192.168.0.55'))->toBeTrue()
        ->and(IpMatcher::contains('192.168.0.0/24', '192.168.1.1'))->toBeFalse()
        ->and(IpMatcher::contains('10.0.0.1', '10.0.0.1'))->toBeTrue();
});

test('cidr contains ipv6', function () {
    expect(IpMatcher::contains('2001:db8::/32', '2001:db8:1234::1'))->toBeTrue()
        ->and(IpMatcher::contains('2001:db8::/32', '2001:db9::1'))->toBeFalse();
});

test('ipv6 key aggregates to /64', function () {
    expect(IpMatcher::key('2001:db8:abcd:1234:5678::1'))->toBe('2001:db8:abcd:1234::/64')
        ->and(IpMatcher::key('203.0.113.9'))->toBe('203.0.113.9');
});

test('invalid cidr rejected', function () {
    expect(IpMatcher::isValidCidr('999.1.1.1'))->toBeFalse()
        ->and(IpMatcher::isValidCidr('10.0.0.0/33'))->toBeFalse()
        ->and(IpMatcher::isValidCidr('10.0.0.0/8'))->toBeTrue();
});

test('ipset binary search matches overlapping ranges', function () {
    $set = IpSet::fromEntries([
        ['cidr' => '10.0.0.0/8', 'id' => 'a'],
        ['cidr' => '10.1.2.0/24', 'id' => 'b'],
        ['cidr' => '192.168.1.1', 'id' => 'c'],
    ]);
    expect($set->contains('10.1.2.5'))->toBeTrue()
        ->and($set->contains('192.168.1.1'))->toBeTrue()
        ->and($set->contains('172.16.0.1'))->toBeFalse()
        ->and($set->match('10.255.255.255'))->toBe('a');
});

test('ipset survives serialization', function () {
    $set = IpSet::fromEntries([['cidr' => '2001:db8::/32']]);
    $restored = IpSet::fromArray($set->toArray());
    expect($restored->contains('2001:db8::1'))->toBeTrue();
});
