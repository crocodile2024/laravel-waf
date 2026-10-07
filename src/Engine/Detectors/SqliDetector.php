<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Engine\Detectors;

/**
 * Token-basierte SQL-Injection-Erkennung (angelehnt an libinjection).
 *
 * Der Wert wird in drei Kontexten tokenisiert (ohne Anführungszeichen, innerhalb
 * '…' und innerhalb "…"). Aus den ersten Tokens entsteht ein Fingerprint, der
 * gegen typische Injektionsmuster geprüft wird.
 *
 * Token-Typen: s=String, n=Zahl, b=Bareword, k=Schlüsselwort, U=UNION,
 * E=SELECT/INSERT/…, &=Logik (AND/OR), o=Operator, f=Funktion, c=Kommentar,
 * (=Klammer auf, )=Klammer zu, ;=Semikolon, ,=Komma, v=Variable (@x).
 */
final class SqliDetector implements Detector
{
    private const LOGIC = ['and', 'or', 'xor', 'div', '&&', '||', 'not', 'rlike', 'like', 'regexp', 'sounds', 'is', 'between'];

    private const STATEMENTS = ['select', 'insert', 'update', 'delete', 'drop', 'create', 'alter', 'truncate', 'exec', 'execute', 'declare', 'shutdown', 'replace', 'merge', 'grant', 'revoke', 'rename', 'handler', 'load', 'call', 'waitfor', 'having', 'order', 'group', 'procedure', 'into', 'from', 'where', 'limit', 'offset', 'case', 'when', 'then', 'else', 'end', 'null', 'true', 'false', 'outfile', 'dumpfile', 'information_schema', 'sysobjects', 'syscolumns', 'pg_sleep', 'delay', 'mysql', 'table', 'database', 'values', 'set', 'begin', 'if', 'collate', 'escape', 'by', 'asc', 'desc', 'all', 'distinct', 'top', 'cast', 'convert'];

    private const FUNCTIONS = ['sleep', 'benchmark', 'pg_sleep', 'extractvalue', 'updatexml', 'load_file', 'char', 'chr', 'concat', 'concat_ws', 'group_concat', 'version', 'database', 'user', 'current_user', 'system_user', 'session_user', 'ascii', 'substring', 'substr', 'mid', 'length', 'hex', 'unhex', 'if', 'ifnull', 'isnull', 'coalesce', 'count', 'cast', 'convert', 'md5', 'sha1', 'ord', 'exp', 'floor', 'rand', 'name_const', 'row', 'json_keys', 'make_set', 'elt', 'dbms_pipe', 'utl_inaddr', 'xp_cmdshell', 'sp_executesql', 'waitfor', 'randomblob', 'sqlite_version', '@@version', 'char_length', 'lower', 'upper', 'unicode', 'nchar', 'pg_read_file', 'lo_import', 'dblink', 'sys_eval', 'sys_exec', 'utl_http', 'dbms_lock', 'gtid_subset', 'polygon', 'multipoint', 'linestring', 'geometrycollection', 'exp', 'st_latfromgeohash'];

    /**
     * Fingerprint-Muster (regulär auf dem Fingerprint).
     */
    private const PATTERNS = [
        '/^s&[nsvf(b]/',      // ' OR 1… / ' OR 'a… / ' AND sleep(
        '/^s&[nsvb]o[nsvf(b]/',
        '/^so[nsv(f]&/',      // '=' or '
        '/^s[o&][nsvbf(]+c$/',
        '/^s;[Ek]/',          // '; DROP …
        '/^n;[Ek]/',
        '/^s\)+[&;U]/',       // ') OR … / '); DROP / ') UNION
        '/^n\)+[&;U]/',
        '/^[sn]\)?U/',        // ' UNION / 1 UNION
        '/^s?U[E(]/',
        '/^[sn]&f\(/',        // 1 AND sleep(
        '/^n&[nsvb]o[nsvb]/', // 1 OR 1=1
        '/^n&[nsv]c?$/',      // 1 OR 1
        '/^n&[nsvf(]+c/',
        '/^b&[nsv]o[nsv]/',   // admin OR 1=1 (Bareword-Kontext)
        '/^sc$/',             // admin'--
        '/^s&c?$/',           // ' or --
        '/^[sn](o|&)f\(/',    // '||sleep( / 1-sleep(
        '/^f\([nsv,]*\)[o&;U]/', // sleep(5)# / sleep(5) and
        '/^[sn];?E/',         // 1;SELECT
        '/^E\(/',
        '/^[sn]o\(E/',        // '=(select
        '/^[sn]&\(E/',        // ' and (select
        '/^[sn]&\(?[nsb]o/',
        '/^v[o&;]/',          // @@version…
        '/^[sn]o[nsvf(]+&/',
        '/^f\(E/',
        '/^kf\(/',            // waitfor delay
        '/^s\)?;?k/',         // '; shutdown / ') waitfor
    ];

    public function detect(string $value): ?string
    {
        if (strlen($value) < 2 || ! preg_match('/[\'"`\-#;()=&|@\/*]|\b(?:union|select|or|and|sleep|benchmark|waitfor)\b/i', $value)) {
            return null;
        }

        $lower = strtolower($value);
        foreach (['', "'", '"'] as $quote) {
            $tokens = $this->tokenize($quote.$lower, $quote);
            $fp = $this->fingerprint($tokens);
            if ($fp === '') {
                continue;
            }
            foreach (self::PATTERNS as $pattern) {
                if (preg_match($pattern, $fp)) {
                    // Kontextbeginn mit Quote muss tatsächlich einen String schließen.
                    if ($quote !== '' && $fp[0] === 's' && ! str_contains($lower, $quote)) {
                        continue 2;
                    }

                    return 'sqli:'.($quote === '' ? 'n' : $quote).':'.$fp;
                }
            }
        }

        return null;
    }

    /**
     * @param  array<int, array{0: string, 1: string}>  $tokens
     */
    private function fingerprint(array $tokens): string
    {
        $fp = '';
        foreach ($tokens as [$type]) {
            $fp .= $type;
            if (strlen($fp) >= 8) {
                break;
            }
        }

        return $fp;
    }

    /**
     * @return array<int, array{0: string, 1: string}>
     */
    private function tokenize(string $s, string $startQuote): array
    {
        $tokens = [];
        $len = strlen($s);
        $i = 0;

        while ($i < $len && count($tokens) < 12) {
            $c = $s[$i];

            // Whitespace
            if (ctype_space($c) || $c === "\0" || $c === "\xa0") {
                $i++;

                continue;
            }

            // Strings
            if ($c === "'" || $c === '"' || $c === '`') {
                $end = $i + 1;
                while ($end < $len) {
                    if ($s[$end] === '\\') {
                        $end += 2;

                        continue;
                    }
                    if ($s[$end] === $c) {
                        if (($s[$end + 1] ?? '') === $c) {
                            $end += 2;

                            continue;
                        }
                        break;
                    }
                    $end++;
                }
                // Backtick-Bezeichner sind Barewords
                $tokens[] = [$c === '`' ? 'b' : 's', substr($s, $i, $end - $i + 1)];
                $i = $end + 1;

                continue;
            }

            // Kommentare
            if ($c === '#' || ($c === '-' && ($s[$i + 1] ?? '') === '-')) {
                $tokens[] = ['c', substr($s, $i)];
                break;
            }
            if ($c === '/' && ($s[$i + 1] ?? '') === '*') {
                $end = strpos($s, '*/', $i + 2);
                $comment = $end === false ? substr($s, $i) : substr($s, $i, $end - $i + 2);
                // MySQL-Versionskommentar: Inhalt wird ausgeführt → weiter tokenisieren
                if (($s[$i + 2] ?? '') === '!') {
                    $i += 3;
                    while ($i < $len && ctype_digit($s[$i])) {
                        $i++;
                    }

                    continue;
                }
                if ($end === false) {
                    $tokens[] = ['c', $comment];
                    break;
                }
                $i = $end + 2;

                continue;
            }

            // Zahlen
            if (ctype_digit($c) || ($c === '.' && ctype_digit($s[$i + 1] ?? ''))) {
                if (preg_match('/\G(0x[0-9a-f]+|0b[01]+|\d*\.?\d+(e[+-]?\d+)?)/A', $s, $m, 0, $i)) {
                    $tokens[] = ['n', $m[0]];
                    $i += strlen($m[0]);

                    continue;
                }
            }

            // Variablen
            if ($c === '@') {
                preg_match('/\G@@?[a-z0-9_.$]*/A', $s, $m, 0, $i);
                $match = $m[0] ?? '';
                $tokens[] = ['v', $match];
                $i += max(1, strlen($match));

                continue;
            }

            // Wörter
            if (ctype_alpha($c) || $c === '_' || $c === '$' || ord($c) >= 0x80) {
                preg_match('/\G[a-z0-9_$.\x80-\xff]+/A', $s, $m, 0, $i);
                $match = $m[0] ?? '';
                $word = rtrim($match, '.');
                $i += max(1, strlen($match));
                $next = $this->peekNonSpace($s, $i);
                $tokens[] = [$this->classifyWord($word, $next), $word];

                continue;
            }

            if ($c === '(' || $c === ')' || $c === ';' || $c === ',') {
                $tokens[] = [$c, $c];
                $i++;

                continue;
            }

            if ($c === '&' && ($s[$i + 1] ?? '') === '&') {
                $tokens[] = ['&', '&&'];
                $i += 2;

                continue;
            }
            if ($c === '|' && ($s[$i + 1] ?? '') === '|') {
                $tokens[] = ['&', '||'];
                $i += 2;

                continue;
            }

            if (str_contains('=<>!+-*/%^&|~:', $c)) {
                preg_match('/\G[=<>!+\-*\/%^&|~:]+/A', $s, $m, 0, $i);
                $match = $m[0] ?? '';
                $tokens[] = ['o', $match];
                $i += max(1, strlen($match));

                continue;
            }

            // Sonstige Zeichen (z. B. Satzzeichen) beenden die Analyse.
            $tokens[] = ['?', $c];
            $i++;
        }

        // Aufeinanderfolgende Strings/Operatoren zusammenfassen
        $merged = [];
        foreach ($tokens as $t) {
            $last = end($merged);
            if ($last !== false && $last[0] === $t[0] && ($t[0] === 'o' || $t[0] === 'b')) {
                continue;
            }
            $merged[] = $t;
        }

        return $merged;
    }

    private function peekNonSpace(string $s, int $i): string
    {
        $len = strlen($s);
        while ($i < $len) {
            if (! ctype_space($s[$i])) {
                // Inline-Kommentar zwischen Funktionsname und Klammer überspringen
                if ($s[$i] === '/' && ($s[$i + 1] ?? '') === '*') {
                    $end = strpos($s, '*/', $i + 2);
                    if ($end === false) {
                        return '';
                    }
                    $i = $end + 2;

                    continue;
                }

                return $s[$i];
            }
            $i++;
        }

        return '';
    }

    private function classifyWord(string $word, string $next): string
    {
        if ($word === 'union') {
            return 'U';
        }
        if (in_array($word, self::LOGIC, true)) {
            return '&';
        }
        if ($next === '(' && (in_array($word, self::FUNCTIONS, true) || in_array($word, self::STATEMENTS, true))) {
            return in_array($word, ['select', 'values'], true) ? 'E' : 'f';
        }
        if (in_array($word, ['select', 'insert', 'update', 'delete', 'drop', 'create', 'alter', 'truncate', 'exec', 'execute', 'declare', 'shutdown', 'grant', 'handler'], true)) {
            return 'E';
        }
        if (in_array($word, self::STATEMENTS, true)) {
            return 'k';
        }
        if (in_array($word, ['true', 'false', 'null'], true)) {
            return 'n';
        }

        return 'b';
    }
}
