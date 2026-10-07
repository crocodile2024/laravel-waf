<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Console\Commands;

use Crocodile2024\WAF\Engine\RequestContext;
use Crocodile2024\WAF\Engine\Rules\RuleMatcher;
use Crocodile2024\WAF\Services\RuleRegistry;
use Illuminate\Console\Command;

class BenchmarkCommand extends Command
{
    protected $signature = 'waf:benchmark {--iterations=2000} {--max-p95=2.0}';

    protected $description = 'Misst die Engine-Latenz mit einem Testkorpus (p50/p95/p99).';

    public function handle(RuleRegistry $registry): int
    {
        $plan = $registry->current();
        $samples = [
            ['method' => 'GET', 'path' => '/', 'query' => ['page' => '1', 'sort' => 'name']],
            ['method' => 'POST', 'path' => '/kontakt', 'body' => ['name' => 'Max Mustermann', 'email' => 'max@example.de', 'nachricht' => 'Guten Tag, bitte um Rückruf.']],
            ['method' => 'GET', 'path' => '/suche', 'query' => ['q' => 'laptop 16gb', 'kategorie' => 'elektronik']],
        ];
        $iterations = max(100, (int) $this->option('iterations'));
        $times = [];

        for ($i = 0; $i < $iterations; $i++) {
            $sample = $samples[$i % count($samples)];
            $ctx = RequestContext::make($sample);
            $start = hrtime(true);
            $matcher = new RuleMatcher($ctx);
            foreach ($plan->request as $rule) {
                if ($rule['pl'] <= 1) {
                    $matcher->match($rule);
                }
            }
            $times[] = (hrtime(true) - $start) / 1e6;
        }

        sort($times);
        $p = fn (float $q) => $times[(int) floor($q * (count($times) - 1))];
        $p50 = $p(0.50);
        $p95 = $p(0.95);
        $p99 = $p(0.99);

        $this->table(['Perzentil', 'Latenz (ms)'], [
            ['p50', number_format($p50, 4)],
            ['p95', number_format($p95, 4)],
            ['p99', number_format($p99, 4)],
        ]);

        $max = (float) $this->option('max-p95');
        if ($p95 > $max) {
            $this->error(sprintf('p95 %.4f ms überschreitet das Budget von %.1f ms.', $p95, $max));

            return self::FAILURE;
        }
        $this->info(sprintf('p95 %.4f ms liegt innerhalb des Budgets (%.1f ms).', $p95, $max));

        return self::SUCCESS;
    }
}
