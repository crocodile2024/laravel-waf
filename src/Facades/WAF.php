<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Facades;

use Crocodile2024\WAF\Engine\Mode;
use Crocodile2024\WAF\WAFManager;
use Illuminate\Support\Facades\Facade;

/**
 * @method static \Crocodile2024\WAF\Models\Ban ban(string $ip, ?int $minutes = null, string $reason = 'manuell')
 * @method static void unban(string $ip)
 * @method static bool isBanned(string $ip)
 * @method static float score(string $ip, int $points, string $reason = '')
 * @method static \Crocodile2024\WAF\Models\IpEntry allow(string $ip, ?string $comment = null, ?\DateTimeInterface $until = null)
 * @method static Mode mode()
 * @method static void extend(string $name, \Closure $factory)
 *
 * @see \Crocodile2024\WAF\WAFManager
 */
final class WAF extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return WAFManager::class;
    }
}
