<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Engine;

use Closure;
use Crocodile2024\WAF\Support\IpMatcher;
use Illuminate\Http\Request;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Str;
use Throwable;

/**
 * Unveränderliches Abbild eines Requests für die Prüfung.
 *
 * Wird pro Request neu erzeugt (Octane-kompatibel). Parameter werden flach
 * mit Punkt-Notation abgelegt (`user.address.street`).
 */
final class RequestContext
{
    /** @var (Closure(): ?string)|null */
    private ?Closure $routeResolver;

    /** @var (Closure(): array{0: bool, 1: string|int|null})|null */
    private ?Closure $userResolver;

    private bool $routeResolved = false;

    private ?string $routeName = null;

    /** @var array{0: bool, 1: string|int|null}|null */
    private ?array $user = null;

    public readonly ContextAttributes $attributes;

    /**
     * @param  array<string, string>  $query
     * @param  array<string, string>  $body
     * @param  array<string, string>  $headers
     * @param  array<string, string>  $cookies
     * @param  array<int, array{field: string, name: string, extension: string, mime: string, client_mime: string, size: int, path: string}>  $files
     * @param  array<int, string>  $queryNames
     * @param  array<int, string>  $bodyNames
     * @param  array<int, string>  $routeMiddleware
     */
    public function __construct(
        public readonly string $id,
        public readonly string $ip,
        public readonly string $ipKey,
        public readonly string $method,
        public readonly string $host,
        public readonly string $path,
        public readonly string $uri,
        public readonly array $query,
        public readonly array $body,
        public readonly array $headers,
        public readonly array $cookies,
        public readonly array $files,
        public readonly array $queryNames,
        public readonly array $bodyNames,
        public readonly string $userAgent,
        public readonly string $contentType,
        public readonly int $contentLength,
        public readonly string $rawBody,
        public readonly int $headerBytes,
        public readonly int $headerCount,
        public readonly int $duplicateContentLength,
        public readonly bool $bodyTooDeep,
        public readonly bool $bodyInvalid,
        public readonly bool $acceptsHtml,
        public readonly array $routeMiddleware = [],
        ?Closure $routeResolver = null,
        ?Closure $userResolver = null,
    ) {
        $this->routeResolver = $routeResolver;
        $this->userResolver = $userResolver;
        $this->attributes = new ContextAttributes;
    }

    /**
     * Erzeugt den Kontext aus einem Laravel-Request.
     *
     * @param  array{max_body_bytes?: int, json_max_depth?: int, ipv6_prefix?: int}  $options
     */
    public static function fromRequest(Request $request, array $options = []): self
    {
        $maxBody = (int) ($options['max_body_bytes'] ?? 65536);
        $maxDepth = (int) ($options['json_max_depth'] ?? 32);
        $v6Prefix = (int) ($options['ipv6_prefix'] ?? 64);

        $ip = (string) ($request->ip() ?? '0.0.0.0');

        $tooDeep = false;
        $invalid = false;

        $query = [];
        $queryNames = [];
        self::flatten($request->query->all(), '', $query, $queryNames, 0, $maxDepth, $tooDeep);

        $contentType = strtolower((string) $request->headers->get('Content-Type', ''));
        $rawBody = '';
        $body = [];
        $bodyNames = [];
        $method = strtoupper($request->getMethod());

        if (! in_array($method, ['GET', 'HEAD', 'OPTIONS'], true) || $request->getContent() !== '') {
            $content = '';
            try {
                $content = (string) $request->getContent();
            } catch (Throwable) {
                // Stream bereits gelesen o. Ä.
            }
            $rawBody = strlen($content) > $maxBody ? substr($content, 0, $maxBody) : $content;

            if (str_contains($contentType, 'json')) {
                if ($content !== '') {
                    try {
                        $decoded = json_decode($content, true, 512, JSON_THROW_ON_ERROR);
                        if (is_array($decoded)) {
                            self::flatten($decoded, '', $body, $bodyNames, 0, $maxDepth, $tooDeep);
                        } else {
                            $body[''] = self::scalar($decoded);
                        }
                    } catch (Throwable $e) {
                        // Zu tief verschachteltes JSON wirft ebenfalls; als "zu tief" werten.
                        if (str_contains($e->getMessage(), 'depth')) {
                            $tooDeep = true;
                        } else {
                            $invalid = true;
                        }
                    }
                }
            } else {
                self::flatten($request->request->all(), '', $body, $bodyNames, 0, $maxDepth, $tooDeep);
            }
        }

        $headers = [];
        $headerBytes = 0;
        $headerCount = 0;
        foreach ($request->headers->all() as $name => $values) {
            $values = array_map('strval', array_filter((array) $values, 'is_scalar'));
            $headerCount += max(1, count($values));
            $headers[strtolower((string) $name)] = implode(', ', $values);
            foreach ($values as $v) {
                $headerBytes += strlen((string) $name) + strlen($v) + 4;
            }
        }
        $duplicateContentLength = count((array) $request->headers->all('content-length'));

        $cookies = [];
        foreach ($request->cookies->all() as $name => $value) {
            $cookies[(string) $name] = is_scalar($value) ? (string) $value : (string) json_encode($value);
        }

        $files = [];
        self::collectFiles($request->files->all(), '', $files);

        $accept = strtolower((string) $request->headers->get('Accept', ''));
        $acceptsHtml = in_array($method, ['GET', 'HEAD'], true)
            && (str_contains($accept, 'text/html') || $accept === '' || $accept === '*/*')
            && ! $request->expectsJson();

        $routeMiddleware = [];
        $routeName = null;
        $routeResolved = false;
        $routeResolver = static function () use ($request, &$routeMiddleware): ?string {
            try {
                $route = $request->route();
                if ($route === null) {
                    $route = app('router')->getRoutes()->match($request);
                }

                return $route->getName();
            } catch (Throwable) {
                return null;
            }
        };

        $userResolver = static function () use ($request): array {
            try {
                $user = $request->user();
            } catch (Throwable) {
                $user = null;
            }

            return [$user !== null, $user?->getAuthIdentifier()];
        };

        return new self(
            id: (string) Str::ulid(),
            ip: $ip,
            ipKey: IpMatcher::key($ip, $v6Prefix),
            method: $method,
            host: strtolower((string) $request->getHost()),
            path: '/'.ltrim(rawurldecode($request->getPathInfo()), '/'),
            uri: (string) $request->server('REQUEST_URI', $request->getRequestUri()),
            query: $query,
            body: $body,
            headers: $headers,
            cookies: $cookies,
            files: $files,
            queryNames: array_values(array_unique($queryNames)),
            bodyNames: array_values(array_unique($bodyNames)),
            userAgent: (string) $request->headers->get('User-Agent', ''),
            contentType: $contentType,
            contentLength: (int) $request->headers->get('Content-Length', '0'),
            rawBody: $rawBody,
            headerBytes: $headerBytes,
            headerCount: $headerCount,
            duplicateContentLength: $duplicateContentLength,
            bodyTooDeep: $tooDeep,
            bodyInvalid: $invalid,
            acceptsHtml: $acceptsHtml,
            routeMiddleware: $routeMiddleware,
            routeResolver: $routeResolver,
            userResolver: $userResolver,
        );
    }

    /**
     * Minimaler Kontext für Tests und den Regel-Tester.
     *
     * @param  array<string, mixed>  $data
     */
    public static function make(array $data = []): self
    {
        $tooDeep = false;
        $query = [];
        $queryNames = [];
        self::flatten((array) ($data['query'] ?? []), '', $query, $queryNames, 0, 32, $tooDeep);
        $body = [];
        $bodyNames = [];
        self::flatten((array) ($data['body'] ?? []), '', $body, $bodyNames, 0, 32, $tooDeep);
        $headers = array_change_key_case(array_map('strval', (array) ($data['headers'] ?? [])), CASE_LOWER);
        $ip = (string) ($data['ip'] ?? '203.0.113.10');
        $routeName = $data['route_name'] ?? null;

        return new self(
            id: (string) Str::ulid(),
            ip: $ip,
            ipKey: IpMatcher::key($ip),
            method: strtoupper((string) ($data['method'] ?? 'GET')),
            host: (string) ($data['host'] ?? 'localhost'),
            path: (string) ($data['path'] ?? '/'),
            uri: (string) ($data['uri'] ?? ($data['path'] ?? '/')),
            query: $query,
            body: $body,
            headers: $headers,
            cookies: array_map('strval', (array) ($data['cookies'] ?? [])),
            files: (array) ($data['files'] ?? []),
            queryNames: $queryNames,
            bodyNames: $bodyNames,
            userAgent: (string) ($headers['user-agent'] ?? ''),
            contentType: (string) ($headers['content-type'] ?? ''),
            contentLength: strlen((string) ($data['raw_body'] ?? '')),
            rawBody: (string) ($data['raw_body'] ?? ''),
            headerBytes: (int) array_sum(array_map(static fn ($k, $v) => strlen((string) $k) + strlen((string) $v) + 4, array_keys($headers), $headers)),
            headerCount: count($headers),
            duplicateContentLength: 1,
            bodyTooDeep: $tooDeep,
            bodyInvalid: false,
            acceptsHtml: (bool) ($data['accepts_html'] ?? false),
            routeMiddleware: [],
            routeResolver: static fn (): ?string => is_string($routeName) ? $routeName : null,
            userResolver: static fn (): array => [isset($data['user_id']), $data['user_id'] ?? null],
        );
    }

    public function routeName(): ?string
    {
        if (! $this->routeResolved) {
            $this->routeResolved = true;
            $this->routeName = $this->routeResolver !== null ? ($this->routeResolver)() : null;
        }

        return $this->routeName;
    }

    public function isAuthenticated(): bool
    {
        return $this->resolveUser()[0];
    }

    public function userId(): string|int|null
    {
        return $this->resolveUser()[1];
    }

    /**
     * @return array{0: bool, 1: string|int|null}
     */
    private function resolveUser(): array
    {
        if ($this->user === null) {
            $this->user = $this->userResolver !== null ? ($this->userResolver)() : [false, null];
        }

        return $this->user;
    }

    public function header(string $name): ?string
    {
        return $this->headers[strtolower($name)] ?? null;
    }

    public function paramCount(): int
    {
        return count($this->query) + count($this->body);
    }

    /**
     * @param  array<array-key, mixed>  $data
     * @param  array<string, string>  $out
     * @param  array<int, string>  $names
     */
    private static function flatten(array $data, string $prefix, array &$out, array &$names, int $depth, int $maxDepth, bool &$tooDeep): void
    {
        if ($depth >= $maxDepth) {
            $tooDeep = true;

            return;
        }
        foreach ($data as $key => $value) {
            $key = (string) $key;
            $names[] = $key;
            $full = $prefix === '' ? $key : $prefix.'.'.$key;
            if (is_array($value)) {
                if ($value === []) {
                    $out[$full] = '';
                }
                self::flatten($value, $full, $out, $names, $depth + 1, $maxDepth, $tooDeep);
            } elseif ($value instanceof UploadedFile) {
                continue;
            } else {
                $out[$full] = self::scalar($value);
            }
        }
    }

    private static function scalar(mixed $value): string
    {
        return match (true) {
            $value === null => '',
            $value === true => 'true',
            $value === false => 'false',
            is_scalar($value) => (string) $value,
            default => (string) json_encode($value),
        };
    }

    /**
     * @param  array<array-key, mixed>  $files
     * @param  array<int, array{field: string, name: string, extension: string, mime: string, client_mime: string, size: int, path: string}>  $out
     */
    private static function collectFiles(array $files, string $prefix, array &$out): void
    {
        foreach ($files as $key => $file) {
            $field = $prefix === '' ? (string) $key : $prefix.'.'.$key;
            if (is_array($file)) {
                self::collectFiles($file, $field, $out);

                continue;
            }
            if (! $file instanceof UploadedFile) {
                continue;
            }
            $name = $file->getClientOriginalName();
            $path = $file->getRealPath();
            $mime = '';
            if ($file->isValid() && $path !== false) {
                try {
                    $mime = (string) $file->getMimeType();
                } catch (Throwable) {
                    $mime = '';
                }
            }
            $out[] = [
                'field' => $field,
                'name' => $name,
                'extension' => strtolower(pathinfo($name, PATHINFO_EXTENSION)),
                'mime' => strtolower($mime),
                'client_mime' => strtolower((string) $file->getClientMimeType()),
                'size' => (int) $file->getSize(),
                'path' => $path === false ? '' : $path,
            ];
        }
    }
}
