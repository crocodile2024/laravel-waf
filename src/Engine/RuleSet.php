<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Engine;

/**
 * Kompilierter, sofort auswertbarer Regelplan (in Redis/APCu abgelegt).
 */
final class RuleSet
{
    /**
     * @param  array<int, array<string, mixed>>  $request  nach Priorität sortierte Request-Regeln
     * @param  array<int, array<string, mixed>>  $response
     */
    public function __construct(
        public readonly array $request,
        public readonly array $response,
        public readonly int $version,
    ) {}

    /**
     * @return array{request: array<int, array<string, mixed>>, response: array<int, array<string, mixed>>, version: int}
     */
    public function toArray(): array
    {
        return ['request' => $this->request, 'response' => $this->response, 'version' => $this->version];
    }

    /**
     * @param  array{request?: array<int, array<string, mixed>>, response?: array<int, array<string, mixed>>, version?: int}  $data
     */
    public static function fromArray(array $data): self
    {
        return new self($data['request'] ?? [], $data['response'] ?? [], (int) ($data['version'] ?? 0));
    }
}
