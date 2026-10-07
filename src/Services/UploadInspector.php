<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Services;

use Crocodile2024\WAF\Engine\RequestContext;
use Crocodile2024\WAF\Engine\Rules\RuleMatch;

/**
 * Upload-Prüfung (5.10): Erweiterung/MIME/Magic-Bytes, doppelte Endungen,
 * eingebettete PHP-Tags, SVG mit Script, ZIP-Bomben, optional ClamAV.
 */
class UploadInspector
{
    private const EXECUTABLE_EXT = ['php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'phar', 'phps', 'pht', 'cgi', 'pl', 'py', 'rb', 'sh', 'bash', 'exe', 'dll', 'so', 'jsp', 'jspx', 'asp', 'aspx', 'ashx', 'jar', 'war', 'bat', 'cmd', 'com', 'scr', 'htaccess', 'htpasswd'];

    public function __construct(
        private readonly ConfigManager $config,
        private readonly ClamAvScanner $clamav,
    ) {}

    /**
     * @return array<int, RuleMatch>
     */
    public function inspect(RequestContext $ctx): array
    {
        if ($ctx->files === [] || ! $this->config->get('uploads.enabled', true)) {
            return [];
        }

        $matches = [];
        $allowedExt = array_map('strtolower', (array) $this->config->get('uploads.allowed_extensions', []));
        $allowedMime = array_map('strtolower', (array) $this->config->get('uploads.allowed_mimes', []));
        $maxBytes = (int) $this->config->get('uploads.max_file_bytes', 20 * 1024 * 1024);
        $maxFiles = (int) $this->config->get('uploads.max_files', 20);

        if (count($ctx->files) > $maxFiles) {
            $matches[] = $this->hit('WAF-UPLOAD-006', 'file', null, 'Zu viele Dateien');
        }

        foreach ($ctx->files as $file) {
            $name = $file['name'];
            $ext = $file['extension'];
            $mime = $file['mime'] !== '' ? $file['mime'] : $file['client_mime'];
            $field = 'file.'.$file['field'];

            if ($file['size'] > $maxBytes) {
                $matches[] = $this->hit('WAF-UPLOAD-005', $field, $name, 'Datei zu groß');
            }
            if (str_contains($name, "\0")) {
                $matches[] = $this->hit('WAF-UPLOAD-002', $field, $name, 'Null-Byte im Dateinamen');
            }
            // Doppelte Endung (bild.php.jpg)
            if (preg_match('/\.('.implode('|', self::EXECUTABLE_EXT).')\./i', $name)
                || in_array(strtolower(pathinfo(rtrim($name, '.'), PATHINFO_EXTENSION)), self::EXECUTABLE_EXT, true)) {
                $matches[] = $this->hit('WAF-UPLOAD-003', $field, $name, 'Ausführbare/doppelte Dateiendung');
            }
            if ($allowedExt !== [] && $ext !== '' && ! in_array($ext, $allowedExt, true)) {
                $matches[] = $this->hit('WAF-UPLOAD-001', $field, $name, 'Erweiterung nicht erlaubt: '.$ext);
            }
            if ($allowedMime !== [] && $mime !== '' && ! in_array($mime, $allowedMime, true)) {
                $matches[] = $this->hit('WAF-UPLOAD-001', $field, $name, 'MIME nicht erlaubt: '.$mime);
            }
            // Erweiterung ↔ MIME-Konsistenz
            if ($mime !== '' && ! $this->extensionMatchesMime($ext, $mime)) {
                $matches[] = $this->hit('WAF-UPLOAD-007', $field, $name, 'Erweiterung passt nicht zum MIME-Typ');
            }

            if ($file['path'] !== '' && is_file($file['path'])) {
                $matches = [...$matches, ...$this->inspectContents($field, $file)];
            }
        }

        return $matches;
    }

    /**
     * @param  array{name: string, extension: string, mime: string, size: int, path: string}  $file
     * @return array<int, RuleMatch>
     */
    private function inspectContents(string $field, array $file): array
    {
        $matches = [];
        $head = (string) @file_get_contents($file['path'], false, null, 0, 4096);

        if (preg_match('/<\?php|<\?=|<script\s+language\s*=\s*["\']?php/i', $head)) {
            $matches[] = $this->hit('WAF-UPLOAD-004', $field, $file['name'], 'PHP-Tag in Datei');
        }
        // SVG mit Script/Event-Handlern
        if (($file['extension'] === 'svg' || str_contains($file['mime'], 'svg')) && preg_match('/<script|on\w+\s*=|javascript:|<!entity/i', $head)) {
            $matches[] = $this->hit('WAF-UPLOAD-008', $field, $file['name'], 'SVG mit aktivem Inhalt');
        }
        // Polyglot: Bild-Magic + PHP
        if (preg_match('/^(\xff\xd8\xff|\x89PNG|GIF8|%PDF)/', $head) && preg_match('/<\?php/i', $head)) {
            $matches[] = $this->hit('WAF-UPLOAD-004', $field, $file['name'], 'Polyglot-Datei');
        }

        // ZIP-Bomben: Kompressionsrate
        if (in_array($file['extension'], ['zip', 'docx', 'xlsx', 'odt', 'ods', 'jar'], true) && str_starts_with($head, "PK")) {
            if (($ratio = $this->zipCompressionRatio($file['path'])) !== null
                && $ratio > (int) $this->config->get('uploads.max_compression_ratio', 100)) {
                $matches[] = $this->hit('WAF-UPLOAD-009', $field, $file['name'], 'Verdächtige Kompressionsrate (ZIP-Bombe)');
            }
        }

        if ($this->config->get('clamav.enabled', false) && ($virus = $this->clamav->scan($file['path'])) !== null) {
            $matches[] = $this->hit('WAF-UPLOAD-010', $field, $file['name'], 'Malware erkannt: '.$virus);
        }

        return $matches;
    }

    private function zipCompressionRatio(string $path): ?float
    {
        if (! class_exists(\ZipArchive::class)) {
            return null;
        }
        $zip = new \ZipArchive;
        if ($zip->open($path) !== true) {
            return null;
        }
        $compressed = 0;
        $uncompressed = 0;
        for ($i = 0; $i < min($zip->numFiles, 1000); $i++) {
            $stat = $zip->statIndex($i);
            if ($stat !== false) {
                $compressed += max(1, (int) $stat['comp_size']);
                $uncompressed += (int) $stat['size'];
            }
        }
        $zip->close();

        return $compressed > 0 ? $uncompressed / $compressed : null;
    }

    private function extensionMatchesMime(string $ext, string $mime): bool
    {
        $map = [
            'jpg' => ['image/jpeg'], 'jpeg' => ['image/jpeg'], 'png' => ['image/png'], 'gif' => ['image/gif'],
            'webp' => ['image/webp'], 'pdf' => ['application/pdf'], 'txt' => ['text/plain'],
            'csv' => ['text/plain', 'text/csv', 'application/csv'], 'zip' => ['application/zip', 'application/octet-stream'],
            'svg' => ['image/svg+xml', 'text/plain', 'text/xml', 'application/xml'],
            'docx' => ['application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'application/zip'],
            'xlsx' => ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'application/zip'],
        ];
        if (! isset($map[$ext])) {
            return true;
        }

        return in_array($mime, $map[$ext], true);
    }

    private function hit(string $code, string $target, ?string $value, string $name): RuleMatch
    {
        return new RuleMatch($code, $name, 'critical', 5, $target, $target, (string) $value, null, ['upload']);
    }
}
