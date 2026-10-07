<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Http\Controllers;

use Crocodile2024\WAF\Models\Ban;
use Crocodile2024\WAF\Models\Event;
use Crocodile2024\WAF\Models\StatHourly;
use Crocodile2024\WAF\Services\ConfigManager;
use Crocodile2024\WAF\Services\GeoIpService;
use Crocodile2024\WAF\Support\RedisStore;
use Illuminate\Contracts\View\View;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class DashboardController extends Controller
{
    public function __construct(
        private readonly ConfigManager $config,
        private readonly RedisStore $redis,
        private readonly GeoIpService $geo,
    ) {}

    public function index(): View
    {
        return view('waf::pages.dashboard', [
            'title' => 'Übersicht',
            'metrics' => $this->metrics(),
            'system' => $this->systemStatus(),
            'hints' => $this->hints(),
        ]);
    }

    public function data(Request $request): JsonResponse
    {
        return response()->json([
            'metrics' => $this->metrics(),
            'system' => $this->systemStatus(),
            'charts' => $this->charts(),
        ]);
    }

    /**
     * @return array<string, array<string, int>>
     */
    private function metrics(): array
    {
        $out = [];
        foreach (['24h' => 1, '7d' => 7, '30d' => 30] as $label => $days) {
            $since = now()->subDays($days);
            $out[$label] = [
                'blocked' => (int) Event::query()->where('occurred_at', '>=', $since)->where('outcome', 'blocked')->count(),
                'challenged' => (int) Event::query()->where('occurred_at', '>=', $since)->where('outcome', 'challenged')->count(),
                'logged' => (int) Event::query()->where('occurred_at', '>=', $since)->where('outcome', 'logged')->count(),
                'checked' => $this->checkedCount($days),
            ];
        }
        $out['bans'] = ['active' => (int) Ban::query()->active()->count()];

        return $out;
    }

    private function checkedCount(int $days): int
    {
        $sum = 0;
        for ($h = 0; $h < $days * 24; $h++) {
            $value = $this->redis->get('counter:'.now()->subHours($h)->format('YmdH'));
            $sum += $value !== null ? (int) $value : 0;
        }

        return $sum;
    }

    /**
     * @return array<string, mixed>
     */
    private function systemStatus(): array
    {
        return [
            'redis' => $this->redis->ping(),
            'queue_length' => $this->redis->llen('events:queue'),
            'config_version' => $this->config->version(),
            'geoip_available' => $this->geo->available(),
            'geoip_age_days' => $this->geo->databaseAgeDays(),
            'nodes' => $this->redis->smembers('nodes'),
            'mode' => $this->config->mode()->value,
        ];
    }

    /**
     * @return array<int, string>
     */
    private function hints(): array
    {
        $hints = [];
        $ageDays = now()->diffInDays(now());
        if ($this->config->mode()->value === 'detect') {
            $hints[] = 'Die WAF läuft im Modus „Erkennen“ – Treffer werden geloggt, aber nicht blockiert.';
        }
        if (($age = $this->geo->databaseAgeDays()) !== null && $age > 30) {
            $hints[] = "Die GeoIP-Datenbank ist älter als 30 Tage ({$age} Tage).";
        }
        if (! $this->geo->available()) {
            $hints[] = 'Es ist keine GeoIP-Datenbank hinterlegt – Geo-Funktionen sind deaktiviert.';
        }

        return $hints;
    }

    /**
     * @return array<string, mixed>
     */
    private function charts(): array
    {
        $since = now()->subDays(7);
        $timeline = StatHourly::query()->where('hour', '>=', $since)
            ->selectRaw('hour, outcome, SUM(count) as total')
            ->groupBy('hour', 'outcome')->get()
            ->groupBy(fn ($r) => $r->hour->format('Y-m-d H:00'));

        $topRules = StatHourly::query()->where('hour', '>=', $since)->where('rule_code', '!=', '')
            ->selectRaw('rule_code, SUM(count) as total')->groupBy('rule_code')
            ->orderByDesc('total')->limit(10)->pluck('total', 'rule_code');

        $topCountries = StatHourly::query()->where('hour', '>=', $since)->where('country', '!=', '')
            ->selectRaw('country, SUM(count) as total')->groupBy('country')
            ->orderByDesc('total')->limit(10)->pluck('total', 'country');

        return [
            'timeline' => $timeline,
            'top_rules' => $topRules,
            'top_countries' => $topCountries,
        ];
    }
}
