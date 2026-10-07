<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Services;

use Illuminate\Support\Facades\Http;
use RuntimeException;

/**
 * Lädt GeoLite2-Datenbanken herunter (einziger externer Laufzeit-Aufruf, 5.7).
 * Nur manuell oder per Scheduler, wenn vom Admin aktiviert.
 */
class GeoIpUpdater
{
    public function __construct(
        private readonly ConfigManager $config,
    ) {}

    /**
     * @return array<string, bool>
     */
    public function update(): array
    {
        $license = (string) $this->config->get('geoip.license_key', '');
        if ($license === '') {
            throw new RuntimeException('Kein MaxMind-Lizenzschlüssel hinterlegt (WAF_MAXMIND_LICENSE).');
        }

        return [
            'GeoLite2-Country' => $this->download('GeoLite2-Country', (string) $this->config->get('geoip.country_db'), $license),
            'GeoLite2-ASN' => $this->download('GeoLite2-ASN', (string) $this->config->get('geoip.asn_db'), $license),
        ];
    }

    private function download(string $edition, string $target, string $license): bool
    {
        if ($target === '') {
            return false;
        }
        $url = 'https://download.maxmind.com/app/geoip_download'
            .'?edition_id='.$edition.'&license_key='.urlencode($license).'&suffix=tar.gz';

        $response = Http::timeout(120)->get($url);
        if (! $response->successful()) {
            return false;
        }

        $tmp = tempnam(sys_get_temp_dir(), 'waf_geo');
        file_put_contents($tmp, $response->body());
        $extracted = $this->extractMmdb($tmp, $edition);
        @unlink($tmp);
        if ($extracted === null) {
            return false;
        }
        @mkdir(dirname($target), 0775, true);
        $ok = @rename($extracted, $target) || (copy($extracted, $target) && @unlink($extracted));

        return (bool) $ok;
    }

    private function extractMmdb(string $tarGz, string $edition): ?string
    {
        try {
            $phar = new \PharData($tarGz);
            $dir = sys_get_temp_dir().'/waf_geo_'.uniqid();
            $phar->extractTo($dir, null, true);
            $files = glob($dir.'/*/'.$edition.'.mmdb') ?: glob($dir.'/'.$edition.'.mmdb') ?: [];

            return $files[0] ?? null;
        } catch (\Throwable) {
            return null;
        }
    }
}
