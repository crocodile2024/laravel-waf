<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Engine\Rules;

use Crocodile2024\WAF\Engine\RequestContext;

/**
 * Liefert die Prüfwerte eines Regelziels als Liste [Parametername, Wert].
 */
final class TargetResolver
{
    public const STATIC_TARGETS = [
        'path', 'uri', 'method', 'ip', 'country', 'asn', 'user_agent', 'route_name', 'authenticated',
        'user_id', 'raw_body', 'host', 'content_type',
        'query.*', 'query_names', 'body.*', 'body_names', 'args.*', 'args_names',
        'header.*', 'header_names', 'cookie.*', 'cookie_names',
        'file.name', 'file.extension', 'file.mime', 'file.size',
    ];

    public const PREFIX_TARGETS = ['query.', 'body.', 'args.', 'header.', 'cookie.'];

    public static function isValid(string $target): bool
    {
        if (in_array($target, self::STATIC_TARGETS, true)) {
            return true;
        }
        foreach (self::PREFIX_TARGETS as $prefix) {
            if (str_starts_with($target, $prefix) && strlen($target) > strlen($prefix)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return array<int, array{0: string|null, 1: string}>
     */
    public static function values(RequestContext $ctx, string $target): array
    {
        switch ($target) {
            case 'path': return [[null, $ctx->path]];
            case 'uri': return [[null, $ctx->uri]];
            case 'method': return [[null, $ctx->method]];
            case 'ip': return [[null, $ctx->ip]];
            case 'host': return [[null, $ctx->host]];
            case 'content_type': return [[null, $ctx->contentType]];
            case 'country': return $ctx->attributes->country !== null ? [[null, $ctx->attributes->country]] : [];
            case 'asn': return $ctx->attributes->asn !== null ? [[null, (string) $ctx->attributes->asn]] : [];
            case 'user_agent': return [[null, $ctx->userAgent]];
            case 'route_name':
                $name = $ctx->routeName();

                return $name !== null ? [[null, $name]] : [];
            case 'authenticated': return [[null, $ctx->isAuthenticated() ? 'true' : 'false']];
            case 'user_id':
                $id = $ctx->userId();

                return $id !== null ? [[null, (string) $id]] : [];
            case 'raw_body': return $ctx->rawBody !== '' ? [['raw_body', $ctx->rawBody]] : [];
            case 'query.*': return self::pairs($ctx->query, 'query.');
            case 'body.*': return self::pairs($ctx->body, 'body.');
            case 'args.*': return [...self::pairs($ctx->query, 'query.'), ...self::pairs($ctx->body, 'body.')];
            case 'query_names': return self::names($ctx->queryNames, 'query.');
            case 'body_names': return self::names($ctx->bodyNames, 'body.');
            case 'args_names': return [...self::names($ctx->queryNames, 'query.'), ...self::names($ctx->bodyNames, 'body.')];
            case 'header.*': return self::pairs($ctx->headers, 'header.');
            case 'header_names': return self::names(array_keys($ctx->headers), 'header.');
            case 'cookie.*': return self::pairs($ctx->cookies, 'cookie.');
            case 'cookie_names': return self::names(array_map('strval', array_keys($ctx->cookies)), 'cookie.');
            case 'file.name': return array_map(static fn (array $f) => ['file.'.$f['field'], $f['name']], $ctx->files);
            case 'file.extension': return array_map(static fn (array $f) => ['file.'.$f['field'], $f['extension']], $ctx->files);
            case 'file.mime': return array_map(static fn (array $f) => ['file.'.$f['field'], $f['mime'] !== '' ? $f['mime'] : $f['client_mime']], $ctx->files);
            case 'file.size': return array_map(static fn (array $f) => ['file.'.$f['field'], (string) $f['size']], $ctx->files);
        }

        if (str_starts_with($target, 'query.')) {
            return self::named($ctx->query, substr($target, 6), 'query.');
        }
        if (str_starts_with($target, 'body.')) {
            return self::named($ctx->body, substr($target, 5), 'body.');
        }
        if (str_starts_with($target, 'args.')) {
            $name = substr($target, 5);

            return [...self::named($ctx->query, $name, 'query.'), ...self::named($ctx->body, $name, 'body.')];
        }
        if (str_starts_with($target, 'header.')) {
            $name = strtolower(substr($target, 7));

            return isset($ctx->headers[$name]) ? [['header.'.$name, $ctx->headers[$name]]] : [];
        }
        if (str_starts_with($target, 'cookie.')) {
            return self::named($ctx->cookies, substr($target, 7), 'cookie.');
        }

        return [];
    }

    /**
     * @param  array<array-key, string>  $data
     * @return array<int, array{0: string, 1: string}>
     */
    private static function pairs(array $data, string $prefix): array
    {
        $out = [];
        foreach ($data as $k => $v) {
            $out[] = [$prefix.$k, $v];
        }

        return $out;
    }

    /**
     * @param  array<int, string>  $names
     * @return array<int, array{0: string, 1: string}>
     */
    private static function names(array $names, string $prefix): array
    {
        return array_map(static fn (string $n) => [$prefix.$n, $n], $names);
    }

    /**
     * Ein benannter Parameter; verschachtelte Werte (name.x) werden mit erfasst.
     *
     * @param  array<array-key, string>  $data
     * @return array<int, array{0: string, 1: string}>
     */
    private static function named(array $data, string $name, string $prefix): array
    {
        if (isset($data[$name])) {
            return [[$prefix.$name, $data[$name]]];
        }
        $out = [];
        $needle = $name.'.';
        foreach ($data as $k => $v) {
            if (str_starts_with((string) $k, $needle)) {
                $out[] = [$prefix.$k, $v];
            }
        }

        return $out;
    }
}
