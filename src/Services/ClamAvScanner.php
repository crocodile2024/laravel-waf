<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Services;

use Throwable;

/**
 * ClamAV-INSTREAM-Scan über Unix- oder TCP-Socket (5.10).
 */
class ClamAvScanner
{
    public function __construct(
        private readonly ConfigManager $config,
    ) {}

    public function available(): bool
    {
        $socket = $this->open();
        if ($socket === null) {
            return false;
        }
        fclose($socket);

        return true;
    }

    /**
     * Scannt eine Datei; liefert den Virusnamen oder null (sauber).
     * Bei Nichterreichbarkeit greift fail_mode (Ausnahme bei closed).
     */
    public function scan(string $path): ?string
    {
        $socket = $this->open();
        if ($socket === null) {
            if ($this->config->failClosed()) {
                return 'ClamAV nicht erreichbar (fail_closed)';
            }

            return null;
        }

        try {
            $content = @file_get_contents($path);
            if ($content === false) {
                return null;
            }
            fwrite($socket, "zINSTREAM\0");
            $chunkSize = 8192;
            for ($i = 0; $i < strlen($content); $i += $chunkSize) {
                $chunk = substr($content, $i, $chunkSize);
                fwrite($socket, pack('N', strlen($chunk)).$chunk);
            }
            fwrite($socket, pack('N', 0));
            $response = (string) fgets($socket);

            if (str_contains($response, 'FOUND')) {
                return trim(str_replace(['stream:', 'FOUND'], '', $response));
            }

            return null;
        } catch (Throwable) {
            return $this->config->failClosed() ? 'ClamAV-Fehler (fail_closed)' : null;
        } finally {
            fclose($socket);
        }
    }

    /**
     * @return resource|null
     */
    private function open()
    {
        $socket = (string) $this->config->get('clamav.socket', '');
        $timeout = (int) $this->config->get('clamav.timeout', 5);
        if ($socket === '') {
            return null;
        }
        $stream = @stream_socket_client($socket, $errno, $errstr, $timeout);
        if ($stream === false) {
            return null;
        }
        stream_set_timeout($stream, $timeout);

        return $stream;
    }
}
