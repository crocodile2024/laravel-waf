<?php

declare(strict_types=1);

namespace Crocodile2024\WAF;

use Closure;
use Crocodile2024\WAF\Engine\Mode;
use Crocodile2024\WAF\Engine\Stages\StageRegistry;
use Crocodile2024\WAF\Models\Ban;
use Crocodile2024\WAF\Models\IpEntry;
use Crocodile2024\WAF\Services\BanService;
use Crocodile2024\WAF\Services\ConfigManager;
use Crocodile2024\WAF\Services\IpListService;
use Crocodile2024\WAF\Services\ReputationService;
use DateTimeInterface;

/**
 * Öffentliche API der WAF für die Host-App (Facade WAF).
 */
class WAFManager
{
    public function __construct(
        private readonly BanService $bans,
        private readonly ReputationService $reputation,
        private readonly IpListService $ipLists,
        private readonly ConfigManager $config,
        private readonly StageRegistry $stages,
    ) {}

    public function ban(string $ip, ?int $minutes = null, string $reason = 'manuell'): Ban
    {
        return $this->bans->ban($ip, $minutes, $reason, 'api');
    }

    public function unban(string $ip): void
    {
        $this->bans->unban($ip);
    }

    public function isBanned(string $ip): bool
    {
        return $this->bans->isBanned($ip);
    }

    public function score(string $ip, int $points, string $reason = ''): float
    {
        return $this->reputation->add($ip, $points);
    }

    public function allow(string $ip, ?string $comment = null, ?DateTimeInterface $until = null): IpEntry
    {
        return $this->ipLists->add('allow', $ip, [
            'comment' => $comment,
            'expires_at' => $until,
            'source' => 'api',
        ]);
    }

    public function mode(): Mode
    {
        return $this->config->mode();
    }

    /**
     * Registriert eine zusätzliche Inspection-Stage (WAF::extend()).
     */
    public function extend(string $name, Closure $factory): void
    {
        $this->stages->register($name, $factory);
    }
}
