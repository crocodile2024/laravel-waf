<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Engine\Rules;

/**
 * Validiert benutzerdefinierte Regex (Syntax + ReDoS-Heuristik).
 */
final class RegexGuard
{
    public const BACKTRACK_LIMIT = 100000;

    public static function compile(string $pattern): string
    {
        return '~'.str_replace('~', '\~', $pattern).'~';
    }

    /**
     * Gibt eine deutsche Fehlermeldung zurück oder null, wenn die Regex zulässig ist.
     */
    public static function validate(string $pattern): ?string
    {
        if ($pattern === '') {
            return 'Der reguläre Ausdruck darf nicht leer sein.';
        }
        if (strlen($pattern) > 4096) {
            return 'Der reguläre Ausdruck ist zu lang (max. 4096 Zeichen).';
        }

        set_error_handler(static fn (): bool => true);
        try {
            $result = preg_match(self::compile($pattern), '');
        } finally {
            restore_error_handler();
        }
        if ($result === false) {
            return 'Ungültiger regulärer Ausdruck: '.preg_last_error_msg();
        }

        if (self::hasNestedQuantifier($pattern)) {
            return 'Der reguläre Ausdruck enthält verschachtelte Quantoren (z. B. „(a+)+“) und wird aus Sicherheitsgründen (ReDoS) abgelehnt.';
        }

        return null;
    }

    /**
     * Erkennt quantifizierte Gruppen, deren Inhalt selbst unbegrenzt quantifiziert ist.
     */
    public static function hasNestedQuantifier(string $pattern): bool
    {
        $len = strlen($pattern);
        /** @var array<int, bool> $stack */
        $stack = [];
        $inClass = false;

        for ($i = 0; $i < $len; $i++) {
            $c = $pattern[$i];

            if ($c === '\\') {
                $i++;

                continue;
            }
            if ($inClass) {
                if ($c === ']') {
                    $inClass = false;
                }

                continue;
            }
            if ($c === '[') {
                $inClass = true;
                if (($pattern[$i + 1] ?? '') === ']') {
                    $i++;
                }

                continue;
            }
            if ($c === '(') {
                $stack[] = false;

                continue;
            }
            if ($c === ')') {
                $inner = array_pop($stack) ?? false;
                $quantified = self::unboundedQuantifierAt($pattern, $i + 1);
                if ($inner && $quantified) {
                    return true;
                }
                // Eine quantifizierte Gruppe macht die umgebende Gruppe "quantifiziert".
                if (($inner || $quantified) && $stack !== []) {
                    $stack[count($stack) - 1] = true;
                }

                continue;
            }
            if (($c === '+' || $c === '*' || $c === '{') && $stack !== [] && self::unboundedQuantifierAt($pattern, $i)) {
                // Possessive/lazy-Modifikatoren ändern nichts an der Einstufung.
                $stack[count($stack) - 1] = true;
            }
        }

        return false;
    }

    private static function unboundedQuantifierAt(string $pattern, int $pos): bool
    {
        $c = $pattern[$pos] ?? '';
        if ($c === '+' || $c === '*') {
            return true;
        }
        if ($c === '{' && preg_match('/^\{\d*,\}/', substr($pattern, $pos, 12))) {
            return true;
        }
        if ($c === '{' && preg_match('/^\{\d*,(\d+)\}/', substr($pattern, $pos, 16), $m)) {
            return (int) $m[1] > 10;
        }

        return false;
    }

    /**
     * Führt preg_match mit begrenztem Backtracking aus.
     * Fehler (z. B. Backtrack-Limit) werden sicherheitshalber als Treffer gewertet.
     */
    public static function match(string $compiled, string $subject, ?int &$offset = null): bool
    {
        $result = @preg_match($compiled, $subject, $m, PREG_OFFSET_CAPTURE);
        if ($result === false) {
            $offset = 0;

            return true;
        }
        if ($result === 1) {
            $offset = $m[0][1];

            return true;
        }

        return false;
    }
}
