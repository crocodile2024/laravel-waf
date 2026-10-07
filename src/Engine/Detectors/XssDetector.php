<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Engine\Detectors;

/**
 * HTML-Kontext-Analyse für Cross-Site-Scripting (angelehnt an libinjection-xss).
 */
final class XssDetector implements Detector
{
    private const URL_ATTRIBUTES = [
        'href', 'src', 'action', 'formaction', 'data', 'xlink:href', 'background', 'lowsrc', 'dynsrc',
        'poster', 'codebase', 'srcdoc', 'to', 'values', 'from', 'by', 'attributename', 'style', 'content',
    ];

    public function detect(string $value): ?string
    {
        if (strlen($value) < 4) {
            return null;
        }
        $s = strtolower($value);

        // URI-Schemata unabhängig vom Tag-Kontext
        $compact = (string) preg_replace('/[\s\x00-\x1f]+/', '', $s);
        if (preg_match('/^(?:javascript|vbscript|livescript|mocha):/', $compact)
            || preg_match('/^data:(?:text\/html|image\/svg\+xml|application\/x?html)/', $compact)) {
            return 'xss:uri';
        }

        if (! str_contains($s, '<')) {
            return null;
        }

        $len = strlen($s);
        $pos = 0;
        while (($lt = strpos($s, '<', $pos)) !== false) {
            $pos = $lt + 1;
            $next = $s[$pos] ?? '';

            if ($next === '!') {
                if (str_starts_with(substr($s, $pos), '!--') && preg_match('/^!--\s*\[if/', substr($s, $pos))) {
                    return 'xss:conditional-comment';
                }
                if (preg_match('/^!\[cdata\[/', substr($s, $pos, 9))) {
                    return 'xss:cdata';
                }

                continue;
            }
            if ($next === '?' || $next === '%') {
                continue;
            }

            if (! preg_match('/\G\/?([a-z][a-z0-9:_\-]*)/A', $s, $m, 0, $pos)) {
                continue;
            }
            $tag = $m[1];
            $tagEnd = $pos + strlen($m[0]);
            $bare = str_contains($tag, ':') ? substr($tag, (int) strrpos($tag, ':') + 1) : $tag;

            // Attributbereich bis zum nächsten '>' (oder Stringende) betrachten
            $gt = strpos($s, '>', $tagEnd);
            $attrs = substr($s, $tagEnd, ($gt === false ? $len : $gt) - $tagEnd);

            // Ohne Attribut-Trennzeichen kein HTML-Tag ("<b" in "a<b" ist unkritisch, sofern kein '>' folgt)
            $hasClose = $gt !== false;
            $firstAttrChar = $s[$tagEnd] ?? '';
            if (! $hasClose && $firstAttrChar !== '' && ! ctype_space($firstAttrChar) && $firstAttrChar !== '/') {
                continue;
            }

            if (in_array($bare, ['script', 'iframe', 'object', 'embed', 'applet', 'base', 'frameset', 'frame', 'xss', 'import', 'portal', 'vmlframe', 'xml', 'plaintext'], true)
                && ($hasClose || str_contains($attrs, '=') || $attrs === '' || ctype_space($firstAttrChar))) {
                if ($m[0][0] !== '/') {
                    return 'xss:tag:'.$bare;
                }
            }

            // Event-Handler: on…= (inkl. Trenner / und Zeilenumbrüche)
            if (preg_match('/(?:^|[\s\/"\'`;])on[a-z]{3,}\s*=/', $attrs)) {
                return 'xss:event:'.$bare;
            }

            if (preg_match_all('/([a-z:\-]+)\s*=\s*(["\'`]?)([^"\'`\s>]*)/', $attrs, $am, PREG_SET_ORDER)) {
                foreach ($am as $attr) {
                    $name = $attr[1];
                    $val = (string) preg_replace('/[\s\x00-\x1f]+/', '', $attr[3]);
                    if (in_array($name, self::URL_ATTRIBUTES, true)
                        && preg_match('/^(?:javascript|vbscript|livescript|data:(?:text\/html|image\/svg|application\/x?html))/', ltrim($val, '"\'`'))) {
                        return 'xss:attr:'.$name;
                    }
                    if ($name === 'style' && preg_match('/expression\s*\(|url\s*\(\s*["\']?\s*javascript|behavior\s*:|-moz-binding/', $attrs)) {
                        return 'xss:style';
                    }
                    if ($name === 'srcdoc') {
                        return 'xss:srcdoc';
                    }
                }
            }

            if (in_array($bare, ['svg', 'math', 'style', 'meta', 'link', 'form', 'template', 'animate', 'set', 'handler', 'listener'], true)
                && ($hasClose || $attrs !== '') && $m[0][0] !== '/') {
                if (in_array($bare, ['style', 'meta', 'link', 'form', 'template', 'svg', 'math'], true) && $this->hasActiveContent($s, $tagEnd)) {
                    return 'xss:tag:'.$bare;
                }
            }
        }

        return null;
    }

    private function hasActiveContent(string $s, int $from): bool
    {
        $rest = substr($s, $from, 2048);

        return (bool) preg_match('/http-equiv\s*=\s*["\']?refresh|<script|javascript:|on[a-z]{3,}\s*=|expression\s*\(|@import|xlink:href|<animate|<set|<foreignobject|rel\s*=\s*["\']?import|formaction|<maction|<mglyph|<mtext|<annotation-xml/', $rest);
    }
}
