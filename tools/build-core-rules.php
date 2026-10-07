<?php

declare(strict_types=1);

/**
 * Erzeugt resources/rules/core-v1.json aus dieser lesbaren Definition.
 *
 * Aufruf: php tools/build-core-rules.php
 */

$T = ['urlDecodeUni', 'htmlEntityDecode', 'utf8Normalize', 'removeNulls', 'lowercase'];
$TS = [...$T, 'removeComments', 'compressWhitespace'];
$TX = ['urlDecodeUni', 'htmlEntityDecode', 'jsDecode', 'utf8Normalize', 'removeNulls', 'lowercase'];
$TP = ['urlDecodeUni', 'utf8Normalize', 'removeNulls', 'normalizePath', 'lowercase'];

$ARGS = ['args.*', 'cookie.*', 'header.referer'];
$ARGS_ONLY = ['args.*'];

/**
 * @param  array<int, string>  $targets
 * @return array<string, mixed>
 */
function anyRegex(array $targets, string $regex): array
{
    return ['match' => 'any', 'items' => array_map(static fn (string $t) => ['target' => $t, 'operator' => 'regex', 'value' => $regex], $targets)];
}

function anyOp(array $targets, string $op, mixed $value = null): array
{
    return ['match' => 'any', 'items' => array_map(static fn (string $t) => array_filter(['target' => $t, 'operator' => $op, 'value' => $value], static fn ($v) => $v !== null), $targets)];
}

function rule(string $code, string $name, string $description, string $severity, int $pl, int $priority, array $tags, array $transforms, array $conditions, array $action = ['type' => 'score'], string $phase = 'request'): array
{
    return [
        'code' => $code,
        'name' => $name,
        'description' => $description,
        'severity' => $severity,
        'paranoia_level' => $pl,
        'priority' => $priority,
        'phase' => $phase,
        'tags' => $tags,
        'transforms' => $transforms,
        'conditions' => $conditions,
        'action' => $action,
    ];
}

$rules = [];

// ---------------------------------------------------------------- SQL-Injection
$sq = ['sqli', 'owasp-a03'];
$rules[] = rule('WAF-SQLI-001', 'UNION-basierte SQL-Injection', 'Erkennt UNION [ALL] SELECT in Parametern, auch mit Kommentar-Obfuskation.', 'critical', 1, 100, $sq, $TS,
    anyRegex($ARGS, '\bunion\b[\s(]*(?:all\b|distinct\b)?[\s(]*select\b'));
$rules[] = rule('WAF-SQLI-002', 'SQL-Tautologie', 'Erkennt Ausbrüche aus Strings/Zahlen mit OR/AND-Vergleich (z. B. \' OR 1=1).', 'critical', 1, 101, $sq, $TS,
    anyRegex($ARGS, '(?:[\'"`)]|^\s*-?\d+)\s*(?:\bor\b|\band\b|\bxor\b|\|\||&&)\s*[(\'"`\s]*(?:[\w@.]+|\'[^\']*\'|"[^"]*")[)\'"`\s]*(?:=|<=>|<>|!=|>=|<=|<|>|\blike\b|\bregexp\b|\brlike\b|\bis\b|\bin\s*\(|\bbetween\b)'));
$rules[] = rule('WAF-SQLI-003', 'SQL-Tautologie (verkürzt)', 'Erkennt \' OR TRUE, \' OR 1-- und ähnliche boolesche Ausbrüche.', 'critical', 1, 102, $sq, $TS,
    anyRegex($ARGS, '[\'"`)]\s*(?:\bor\b|\band\b|\|\||&&)\s*(?:\bnot\s+)?(?:\btrue\b|\bfalse\b|\bnull\b|\d+\b|[\'"]\w*[\'"]?\s*$|\(\s*select\b|\bexists\s*\(|\bsleep\s*\(|\bif\s*\()'));
$rules[] = rule('WAF-SQLI-004', 'Gestapelte SQL-Abfragen', 'Erkennt Stacked Queries (; DROP TABLE …).', 'critical', 1, 103, $sq, $TS,
    anyRegex($ARGS, ';\s*(?:(?:drop|truncate|alter|create)\s+(?:table|database|schema|user|procedure|function|view|trigger|index)\b|delete\s+from\b|insert\s+into\b|update\s+[\w`."\[\]]+\s+set\b|select\b.{0,200}?\bfrom\b|select\s+(?:@@|\d|sleep|pg_sleep|benchmark|version|user|load_file|\*)|exec(?:ute)?\s+(?:xp_|sp_|master\.|\()|declare\s+@|shutdown\b|waitfor\s+delay\b|grant\s+all\b|copy\s+\w+\s+(?:from|to)\b|set\s+@)'));
$rules[] = rule('WAF-SQLI-005', 'Zeitbasierte SQL-Injection', 'Erkennt SLEEP(), BENCHMARK(), PG_SLEEP(), WAITFOR DELAY u. Ä.', 'critical', 1, 104, $sq, $TS,
    anyRegex($ARGS, '\b(?:sleep|pg_sleep|benchmark|randomblob)\s*\(\s*[\d\'"(]|\bwaitfor\s+(?:delay|time)\s+[\'"]|\bdbms_lock\s*\.\s*sleep\b|\bdbms_pipe\s*\.\s*receive_message\b|\bpg_sleep_for\s*\('));
$rules[] = rule('WAF-SQLI-006', 'Fehlerbasierte SQL-Injection', 'Erkennt EXTRACTVALUE, UPDATEXML, FLOOR(RAND()) und weitere fehlerbasierte Techniken.', 'critical', 1, 105, $sq, $TS,
    anyRegex($ARGS, '\b(?:extractvalue|updatexml|name_const|gtid_subset|exp\s*\(\s*~|st_latfromgeohash|json_keys\s*\(\s*\(\s*select)\s*\(|\bfloor\s*\(\s*rand\s*\(|\bcount\s*\(\s*\*\s*\)\s*,\s*concat\s*\(|\butl_inaddr\s*\.\s*get_host|\bctxsys\s*\.\s*drithsx|\bconvert\s*\(\s*int\s*,|\bcast\s*\(.{1,100}?\bas\s+(?:int|numeric|signed)\b.{0,10}\)\s*(?:=|>|<|--)'));
$rules[] = rule('WAF-SQLI-007', 'Zugriff auf Systemtabellen', 'Erkennt Abfragen auf information_schema, mysql.user, sysobjects, pg_catalog u. Ä.', 'critical', 1, 106, $sq, $TS,
    anyRegex($ARGS, '\binformation_schema\b|\bmysql\s*\.\s*(?:user|db)\b|\bsys(?:objects|columns|users|databases)\b|\bpg_(?:catalog|shadow|user|tables|namespace|database)\b|\bsqlite_(?:master|schema|temp_master)\b|\ball_(?:tables|tab_columns|users)\b|\buser_(?:tables|tab_columns|objects)\b|\bmsysaccessobjects\b|\bmaster\s*\.\s*(?:dbo|sys)\b|\bsys\s*\.\s*(?:tables|columns|objects|databases|sql_logins)\b|\bdual\b\s*(?:where|union|--|#)'));
$rules[] = rule('WAF-SQLI-008', 'SQL-Kommentar nach Stringabschluss', 'Erkennt admin\'-- und ähnliche Abschlüsse mit Kommentar.', 'error', 1, 107, $sq, $T,
    anyRegex($ARGS, '[\'"`]\s*\)*\s*(?:--[\s\-+]*|#|/\*.*|;\s*(?:--|#|%00|\x00))\s*$|[\'"]\s*\)*\s*;\s*$'));
$rules[] = rule('WAF-SQLI-009', 'SQL-Funktionen nach Stringabschluss', 'Erkennt Verkettungen wie \'||CHR(…) oder \'+CHAR(…).', 'critical', 1, 108, $sq, $TS,
    anyRegex($ARGS, '[\'"`]\s*(?:\|\||\+|&&|\bor\b|\band\b|\bxor\b|-|\*|=|<|>)\s*\(?\s*(?:char|chr|nchar|concat|concat_ws|ascii|substring|substr|mid|hex|unhex|version|database|user|current_user|load_file|sleep|benchmark|if|ifnull|case|select|elt|make_set|ord|length|db_name|@@\w+|utl_\w+|dbms_\w+|pg_\w+)\b'));
$rules[] = rule('WAF-SQLI-010', 'SQL-Dateioperationen und gespeicherte Prozeduren', 'Erkennt INTO OUTFILE, LOAD_FILE, xp_cmdshell, COPY … FROM PROGRAM.', 'critical', 1, 109, $sq, $TS,
    anyRegex($ARGS, '\binto\s+(?:out|dump)file\b|\bload_file\s*\(|\bload\s+data\s+(?:local\s+)?infile\b|\bxp_(?:cmdshell|regread|regwrite|dirtree|fileexist|servicecontrol)\b|\bsp_(?:executesql|oacreate|oamethod|configure|addextendedproc|makewebtask|password|addlogin|addsrvrolemember)\b|\blo_(?:import|export)\s*\(|\bcopy\s+\w+\s+from\s+program\b|\bopenrowset\s*\(|\bopendatasource\s*\(|\butl_(?:http|file)\s*\.'));
$rules[] = rule('WAF-SQLI-011', 'SQL ORDER BY/GROUP BY-Injektion', 'Erkennt Spaltenzählung per ORDER BY n nach Stringabschluss.', 'critical', 1, 110, $sq, $TS,
    anyRegex($ARGS, '(?:[\'"`)]|^\s*\d+)\s*(?:order|group)\s+by\s+(?:\d+|if\s*\(|\(\s*select|\w+\s*(?:--|#|$))|\bhaving\s+\d+\s*=\s*\d+|\bprocedure\s+analyse\s*\('));
$rules[] = rule('WAF-SQLI-012', 'SQL-Systemvariablen', 'Erkennt @@version, @@datadir u. Ä.', 'error', 1, 111, $sq, $TS,
    anyRegex($ARGS, '@@(?:version|datadir|hostname|basedir|tmpdir|servername|language|spid|innodb\w*|global\.|session\.)'));
$rules[] = rule('WAF-SQLI-013', 'SQL CHAR()-Ketten', 'Erkennt per CHAR(n,n,n) zusammengesetzte Zeichenketten.', 'error', 1, 112, $sq, $TS,
    anyRegex($ARGS, '\b(?:char|chr|nchar)\s*\(\s*\d+\s*\)\s*(?:\+|\|\|)\s*(?:char|chr|nchar)\s*\(|\bchar\s*\(\s*\d+\s*,\s*\d+\s*,\s*\d+'));
$rules[] = rule('WAF-SQLI-014', 'SQL-Injection (Token-Analyse)', 'libinjection-artige Token-Analyse auf SQL-Injektionsmuster.', 'critical', 1, 113, $sq, ['urlDecodeUni', 'htmlEntityDecode', 'utf8Normalize', 'removeNulls'],
    anyOp($ARGS_ONLY, 'detect_sqli'));
$rules[] = rule('WAF-SQLI-015', 'Boolesche Blind-SQL-Injection', 'Erkennt AND/OR mit Subqueries und Vergleichsfunktionen.', 'critical', 1, 114, $sq, $TS,
    anyRegex($ARGS, '\b(?:and|or|&&|\|\|)\s+\(?\s*(?:ascii|ord|substr|substring|mid|length|char_length|unicode|hex)\s*\(\s*\(?\s*(?:select|user|database|version|@@)|\b(?:and|or)\s+\d+\s*(?:=|<|>)\s*\(\s*select\b|\b(?:and|or)\s+\(\s*select\s+'));
$rules[] = rule('WAF-SQLI-016', 'SQL-Konstrukt SELECT … FROM', 'Erkennt vollständige SELECT-Anweisungen in Parametern (höheres Fehlalarmrisiko).', 'error', 2, 120, $sq, $TS,
    anyRegex($ARGS, '\bselect\b[\s(]+(?:[\w*@`."\[\],()\s]{1,200}?)\bfrom\b\s+[\w`."\[]|\binsert\s+into\s+[\w`."\[]+\s*(?:\(|values\b|select\b)|\bdelete\s+from\s+[\w`."\[]+\s+where\b|\bdrop\s+(?:table|database)\s+[\w`."\[]'));
$rules[] = rule('WAF-SQLI-017', 'SQL-Informationsfunktionen', 'Erkennt version(), database(), user() u. Ä.', 'warning', 2, 121, $sq, $TS,
    anyRegex($ARGS, '\b(?:version|database|current_user|system_user|session_user|schema|db_name|user_name|current_database|sqlite_version|connection_id|last_insert_id)\s*\(\s*\)'));
$rules[] = rule('WAF-SQLI-018', 'Stringvergleich-Ausbruch', 'Erkennt \'=\' und \'<>\'-Muster.', 'warning', 2, 122, $sq, $TS,
    anyRegex($ARGS, '[\'"]\s*(?:=|<>|!=|\blike\b)\s*[\'"]|[\'"]\s*(?:-|\+|\*|/|%)\s*[\'"]'));
$rules[] = rule('WAF-SQLI-019', 'Hex-kodierte Zeichenketten', 'Erkennt lange 0x-Literale (häufig für Payload-Verschleierung).', 'notice', 3, 130, $sq, $T,
    anyRegex($ARGS, '\b0x[0-9a-f]{10,}\b'));
$rules[] = rule('WAF-SQLI-020', 'MySQL-Versionskommentar', 'Erkennt /*!50000 …*/-Kommentare zur Filterumgehung.', 'error', 1, 115, $sq, ['urlDecodeUni', 'htmlEntityDecode', 'removeNulls', 'lowercase'],
    anyRegex($ARGS, '/\*!\d{0,5}\s*\w|\b(?:select|union|from|where|and|or|order|insert|update|delete)\s*/\*.*?\*/\s*\w|\w\s*/\*.*?\*/\s*(?:select|union|from|where|and|or)\b'));

// ---------------------------------------------------------------- XSS
$xs = ['xss', 'owasp-a03'];
$rules[] = rule('WAF-XSS-001', 'Script-Tag', 'Erkennt <script-Tags.', 'critical', 1, 200, $xs, $TX,
    anyRegex($ARGS, '<\s*/?\s*script[\s>/]|<\s*script\s*$'));
$rules[] = rule('WAF-XSS-002', 'HTML-Event-Handler', 'Erkennt on*=-Attribute in Tags oder nach Attributausbruch.', 'critical', 1, 201, $xs, $TX,
    anyRegex($ARGS, '<[a-z!/?][^>]*?[\s/"\'`]on[a-z]{3,}\s*=|^[^<]*?["\'`][\s/]*on[a-z]{3,}\s*=\s*["\'`]?[\w\s.(\'"`[{]|(?:^|[\s"\'`/])on(?:error|load|click|mouse\w+|focus|blur|key\w+|change|submit|toggle|begin|end|animation\w+|transition\w+|pointer\w+|start|finish|scroll|wheel|drag\w*|drop|copy|paste|cut|input|invalid|reset|search|select|show|play|pause|resize|unload|beforeunload|hashchange|message|popstate|storage|online|offline|pageshow|pagehide|readystatechange|auxclick|contextmenu|dblclick)\s*=\s*["\'`]?\s*(?:[a-z_$][\w$.]*\s*[(`=]|\w+\s*\.|\[|javascript:|top|self|window|this)'));
$rules[] = rule('WAF-XSS-003', 'JavaScript-URI', 'Erkennt javascript:, vbscript: und data:text/html-URIs.', 'critical', 1, 202, $xs, [...$TX, 'removeWhitespace'],
    anyRegex($ARGS, '(?:^|[\'"`=(,\[<>])(?:javascript|vbscript|livescript|mocha):(?:\S*?(?:\(|`|=|&#|\\\\u|//|\balert|\beval|\bwindow|\bdocument|\bthis|\btop|\bself|\blocation|\bprompt|\bconfirm|\bvoid|\bfetch|\bimport))|^(?:javascript|vbscript):\S{3,}|data:(?:text/html|image/svg\+xml|application/(?:x-)?(?:xhtml|javascript|ecmascript))'));
$rules[] = rule('WAF-XSS-004', 'Gefährliche HTML-Tags', 'Erkennt iframe, object, embed, applet, base, frameset, meta refresh u. Ä.', 'critical', 1, 203, $xs, $TX,
    anyRegex($ARGS, '<\s*(?:iframe|object|embed|applet|base|frameset|frame|isindex|bgsound|xss|portal|vmlframe|import|xml:namespace|layer|ilayer)\b[\s/>]|<\s*meta\b[^>]*http-equiv|<\s*link\b[^>]*rel\s*=\s*["\']?(?:import|stylesheet)[^>]*href|<\s*(?:svg|math)\b[^>]*>.*?<\s*(?:script|animate|set|foreignobject|use|maction|mtext|mglyph|a\b|annotation-xml)|<\s*(?:svg|math)[^>]*(?:on[a-z]{3,}\s*=|xlink:href)'));
$rules[] = rule('WAF-XSS-005', 'XSS (Kontextanalyse)', 'HTML-Kontextanalyse auf aktive Inhalte.', 'critical', 1, 204, $xs, $TX,
    anyOp($ARGS, 'detect_xss'));
$rules[] = rule('WAF-XSS-006', 'srcdoc-Attribut', 'Erkennt srcdoc= (eingebettete HTML-Dokumente).', 'critical', 1, 205, $xs, $TX,
    anyRegex($ARGS, '<[^>]*\bsrcdoc\s*='));
$rules[] = rule('WAF-XSS-007', 'Client-seitige Template-Injection', 'Erkennt {{…}}/${…} mit Zugriff auf Konstruktoren oder globale Objekte.', 'critical', 1, 206, $xs, $TX,
    anyRegex($ARGS, '\{\{[^}]{0,200}?(?:constructor|__proto__|\$on|\$eval|\$emit|_c\.|_v\.|\balert\s*\(|\bprompt\s*\(|\bconfirm\s*\(|\beval\s*\(|\bwindow\b|\bdocument\b|\bprocess\b|\brequire\b|\bglobal\b|\bfunction\s*\(|\bimport\s*\(|\[\s*[\'"]\w|toString|valueOf|\bself\b|this\.|\bnew\s)|\$\{[^}]{0,200}?(?:\balert\s*\(|\beval\s*\(|\bprocess\b|\brequire\s*\(|constructor|\bdocument\b|\bwindow\b|\bnew\s+\w|import\s*\(|\bfetch\s*\()|\{\{\s*\d+\s*[*+]\s*\d+\s*\}\}|\$\{\s*\d+\s*[*+]\s*\d+\s*\}|#\{\s*\d+\s*[*+]\s*\d+\s*\}|\{%\s*(?:import|include|set|for|if|debug|load)\b|\{\{\s*(?:config|request|self|cycler|joiner|namespace|lipsum|url_for|get_flashed_messages)\b|<%=?\s*[\w$]+\s*(?:\(|\.|\[)'));
$rules[] = rule('WAF-XSS-008', 'CSS-Ausdrücke', 'Erkennt expression(), -moz-binding, behavior: und @import mit javascript:.', 'error', 1, 207, $xs, [...$TX, 'cssDecode', 'removeComments'],
    anyRegex($ARGS, '\bexpression\s*\(|-moz-binding\s*:|\bbehavior\s*:\s*url|@import\s+[\'"]?\s*(?:javascript|data):|url\s*\(\s*[\'"]?\s*(?:javascript|vbscript):'));
$rules[] = rule('WAF-XSS-009', 'Attributausbruch mit Tag', 'Erkennt "><tag- und \'><tag-Muster.', 'error', 2, 220, $xs, $TX,
    anyRegex($ARGS, '[\'"`]\s*/?\s*>\s*<\s*[a-z!/]'));
$rules[] = rule('WAF-XSS-010', 'DOM-Senken und JS-Ausführung', 'Erkennt document.cookie, eval(, alert( u. Ä. (höheres Fehlalarmrisiko).', 'warning', 2, 221, $xs, $TX,
    anyRegex($ARGS, '\bdocument\s*\.\s*(?:cookie|write|writeln|domain|location)\b|\bwindow\s*\.\s*(?:location|open|name)\b|\.\s*innerhtml\s*=|\b(?:alert|prompt|confirm)\s*[(`]|\bstring\s*\.\s*fromcharcode\s*\(|\batob\s*\(|\bsettimeout\s*\(\s*[\'"`]|\bnew\s+function\s*\('));
$rules[] = rule('WAF-XSS-011', 'Beliebige HTML-Tags', 'Erkennt HTML-Tags mit Attributen (Paranoia 3).', 'notice', 3, 230, $xs, $TX,
    anyRegex($ARGS, '<\s*[a-z][a-z0-9:-]*\s+[a-z:-]+\s*='));
$rules[] = rule('WAF-XSS-012', 'SVG/MathML-Vektoren', 'Erkennt SVG/MathML-Tags (Paranoia 2).', 'warning', 2, 222, $xs, $TX,
    anyRegex($ARGS, '<\s*(?:svg|math|style|form|template|details|marquee|video|audio|source|object)\b[\s/>]'));

// ---------------------------------------------------------------- LFI
$lf = ['lfi', 'owasp-a01'];
$rules[] = rule('WAF-LFI-001', 'Path Traversal', 'Erkennt mehrstufige ../-Sequenzen (auch kodiert).', 'critical', 1, 300, $lf, [...$TP, 'utf8Normalize'],
    anyRegex(['args.*', 'uri', 'cookie.*'], '\.{2,3}[\\\\/]{1,3}\.{2,3}[\\\\/]|(?:^|[\\\\/=])\.{2,3}[\\\\/;]{1,3}[\w.\-/\\\\]{0,200}?(?:etc|proc|windows|winnt|boot|var|usr|root|home|tmp|dev|bin|sys|inetpub|system32|\.ssh|\.env|wp-config|config|\.git)|\.\.;[\\\\/]'));
$rules[] = rule('WAF-LFI-002', 'Zugriff auf Systemdateien', 'Erkennt /etc/passwd, /proc/self/environ, win.ini, .htpasswd u. Ä.', 'critical', 1, 301, $lf, $TP,
    anyRegex(['args.*', 'uri', 'cookie.*'], '/etc/(?:passwd|shadow|group|hosts|issue|hostname|crontab|sudoers|motd|resolv\.conf|apache2?/|nginx/|httpd/|mysql/|php\d*/|ssh/|ssl/|environment|fstab|profile|bashrc)|/proc/(?:self|\d+)/(?:environ|cmdline|fd|maps|status|mem|cwd|exe|root|mounts)|/var/log/(?:apache|nginx|httpd|auth|syslog|messages|secure|mail)|\bboot\.ini\b|\bwin\.ini\b|\bsystem\.ini\b|/windows/(?:system32|win\.ini|repair)|/winnt/|\bsystem32/(?:drivers|config|cmd)|\.htpasswd\b|/\.ssh/(?:id_|authorized_keys|known_hosts)|\bid_(?:rsa|dsa|ecdsa|ed25519)\b|\.bash_history\b|/root/\.|\bwp-config\.php\b|/\.aws/credentials|/\.docker/config|/\.kube/config|/storage/logs/laravel\.log'));
$rules[] = rule('WAF-LFI-003', 'PHP-Stream-Wrapper', 'Erkennt php://, phar://, zip://, data://, expect://, glob:// u. Ä.', 'critical', 1, 302, $lf, $T,
    anyRegex(['args.*', 'cookie.*', 'uri'], '\b(?:php|phar|zip|zlib|data|expect|glob|compress\.zlib|compress\.bzip2|ogg|rar|ssh2(?:\.\w+)?)://'));
$rules[] = rule('WAF-LFI-004', 'Einfaches Path Traversal', 'Erkennt einzelne ../-Sequenzen (Paranoia 2).', 'warning', 2, 310, $lf, $TP,
    anyRegex(['args.*', 'uri'], '(?:^|[\\\\/=])\.\.[\\\\/]'));
$rules[] = rule('WAF-LFI-005', 'Null-Byte-Injektion', 'Erkennt Null-Bytes in Parametern (Dateiendungs-Umgehung).', 'error', 1, 303, $lf, ['urlDecodeUni'],
    anyRegex(['args.*', 'uri', 'cookie.*'], '\x00'));
$rules[] = rule('WAF-LFI-006', 'Windows-Pfade', 'Erkennt absolute Windows-Pfade auf Systemverzeichnisse.', 'error', 1, 304, $lf, $TP,
    anyRegex(['args.*'], '^[a-z]:/(?:windows|winnt|boot\.ini|inetpub|users/[^/]+/(?:appdata|ntuser)|programdata)|\\\\\\\\(?:localhost|127\.0\.0\.1|[\w.-]+)\\\\(?:c\$|admin\$|ipc\$)'));

// ---------------------------------------------------------------- RFI
$rf = ['rfi', 'owasp-a03'];
$includeNames = ['file', 'page', 'include', 'inc', 'path', 'template', 'tpl', 'dir', 'module', 'load', 'lang', 'language', 'pg', 'doc', 'document', 'folder', 'root', 'show', 'site', 'view', 'content', 'conf', 'config', 'layout', 'mod', 'filename', 'class', 'base', 'basepath', 'home', 'theme', 'skin', 'cat', 'action', 'main', 'body', 'src'];
$rules[] = rule('WAF-RFI-001', 'Remote File Inclusion (Parametername)', 'Erkennt externe URLs in typischen Include-Parametern.', 'critical', 1, 400, $rf, $T,
    ['match' => 'any', 'items' => array_map(static fn (string $n) => ['target' => 'args.'.$n, 'operator' => 'regex', 'value' => '^\s*(?:https?|ftps?|smb|\\\\\\\\)[:/]'], $includeNames)]);
$rules[] = rule('WAF-RFI-002', 'Remote File Inclusion (Abschluss-Fragezeichen)', 'Erkennt externe URLs mit abschließendem ? oder Null-Byte.', 'critical', 1, 401, $rf, $T,
    anyRegex(['args.*'], '^\s*(?:https?|ftps?)://[^\s?]+(?:\?+|\x00|%00)\s*$|^\s*(?:https?|ftps?)://\S+\.(?:txt|php\d?|phtml|inc|jpg|gif|png)\?+\s*$'));
$rules[] = rule('WAF-RFI-003', 'Bekannte Web-Shells', 'Erkennt Verweise auf bekannte Web-Shells (c99, r57, …).', 'critical', 1, 402, $rf, $T,
    anyRegex(['args.*', 'uri'], '(?:https?|ftps?)://\S*\b(?:c99|r57|c100|wso|b374k|shell|backdoor|webshell|cmd|phpshell|weevely|alfa)\w*\.(?:txt|php\d?|phtml|jpg|gif)\b'));
$rules[] = rule('WAF-RFI-004', 'UNC-Pfad', 'Erkennt UNC-Pfade (\\\\host\\share) in Parametern.', 'error', 1, 403, $rf, $T,
    anyRegex(['args.*'], '^\s*\\\\\\\\[\w.\-]+\\\\[\w$.\-]+'));
$rules[] = rule('WAF-RFI-005', 'URL mit IP-Adresse als Include', 'Erkennt URLs auf IP-Literale in Parametern (Paranoia 2).', 'warning', 2, 410, $rf, $T,
    anyRegex(['args.*'], '^\s*(?:https?|ftps?)://\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?/\S*\.(?:txt|php|inc|sh|pl|py)'));

// ---------------------------------------------------------------- RCE
$rc = ['rce', 'owasp-a03'];
$cmds = 'cat|tac|ls|id|whoami|uname|wget|curl|nc|ncat|netcat|bash|sh|zsh|dash|ksh|csh|python[23]?|perl|ruby|php\d?|nslookup|rm|chmod|chown|mkfifo|telnet|tftp|powershell|pwsh|cmd|certutil|bitsadmin|base64|ifconfig|ipconfig|netstat|crontab|useradd|systeminfo|socat|busybox|sudo|nohup|xterm|lua|node|java|gcc|awk|sed|xargs|tee|dd|nmap|ping|sleep|echo|printf|env|printenv|set|export|unset|kill|pkill|killall|ps|hostname|uptime|w|who|last|find|locate|grep|head|tail|more|less|nl|od|xxd|strings|tar|zip|unzip|gzip|scp|ssh|ftp|net|reg|wmic|tasklist|taskkill|type|dir|del|copy|move|ren|rundll32|regsvr32|mshta|cscript|wscript|msiexec|schtasks|at|bcdedit|vssadmin|icacls|attrib';
$rules[] = rule('WAF-RCE-001', 'Befehlsverkettung mit Shell-Befehl', 'Erkennt ;, |, `, $( , && gefolgt von bekannten Befehlen.', 'critical', 1, 500, $rc, $T,
    anyRegex(['args.*', 'cookie.*', 'header.user-agent', 'header.referer'], '(?:[;|`\n\r]|\$\(|\|\||&&|\$\{ifs\}|%0a)\s*\{?\s*(?:/(?:usr/)?(?:local/)?s?bin/)?(?:'.$cmds.')(?:\.exe)?(?:[\s<>|;&$`\'"(){},]|\$\{?ifs|$)'));
$rules[] = rule('WAF-RCE-002', 'Shell-Interpreter und Download-Werkzeuge', 'Erkennt /bin/sh, bash -c, cmd /c, PowerShell-Cmdlets, /dev/tcp u. Ä.', 'critical', 1, 501, $rc, $T,
    anyRegex(['args.*', 'cookie.*', 'header.user-agent'], '/(?:usr/)?(?:local/)?s?bin/(?:sh|bash|zsh|dash|ksh|csh|tcsh|busybox|nc|ncat|netcat|perl|python[23]?|php|ruby|wget|curl|env|id|cat|ls|whoami|uname|rm|chmod)\b|\b(?:ba|z|k|da)?sh\s+-[a-z]*c\b|\bcmd(?:\.exe)?\s+/[ck]\b|\bpowershell(?:\.exe)?\s+[-/]|\b(?:iex|invoke-expression|invoke-webrequest|invoke-restmethod|downloadstring|downloadfile|start-process|new-object\s+(?:system\.)?net\.webclient|frombase64string|-encodedcommand|-enc\s+[a-z0-9+/=]{16,})\b|/dev/(?:tcp|udp)/|\bnc(?:at)?\s+-[a-z]{0,5}[elvpcz]|\bmkfifo\s+/|\bpython[23]?\s+-c\b|\bperl\s+-e\b|\bphp\s+-r\b|\bruby\s+-e\b|\bnode\s+-e\b|\bcurl\s+(?:-[a-z]{1,10}\s{1,3}){0,5}https?://\S+\s*\|\s*(?:ba)?sh|\bwget\s+(?:-[a-z]{1,10}\s{1,3}){0,5}(?:https?|ftp)://'));
$rules[] = rule('WAF-RCE-003', 'Shell-Umgehungstechniken', 'Erkennt $IFS, Brace-Expansion {cat,/etc/passwd}, $(…)-Substitution und Wildcard-Pfade.', 'critical', 1, 502, $rc, $T,
    anyRegex(['args.*', 'cookie.*'], '\$\{?ifs\}?|\{\s*(?:'.$cmds.')\s*,[^}]*\}|\$\(\s*(?:'.$cmds.')\b[^)]*\)|`\s*(?:'.$cmds.')\b[^`]*`|/(?:\?\?\?|\?[a-z?]{1,3}|[a-z]\?{1,3}|\*\*?)/(?:\?\?|[a-z?*]{2,6}\?)|/[a-z]\[[a-z]\]+[a-z]*/|\$\{(?:path|home|shell|pwd|hostname):\d|\$\{?(?:[a-z]+)\}?\s*[;|]'));
$rules[] = rule('WAF-RCE-004', 'Shell-Befehle (normalisiert)', 'Erkennt verschleierte Befehle (c\'a\'t, w\\h\\o\\a\\m\\i) nach cmdLine-Normalisierung.', 'critical', 1, 503, $rc, ['urlDecodeUni', 'htmlEntityDecode', 'removeNulls', 'cmdLine'],
    anyRegex(['args.*'], '(?:^|[\s|&`(]|\$\()(?:cat|tac|nl|head|tail|more|less|od|xxd|strings|base64)\s*[<\s]\s*/?(?:etc|proc|var|root|home|usr|tmp|dev|windows)/|(?:^|[\s|&`(]|\$\()(?:whoami|ifconfig|systeminfo|uname\s+-a|id\s*$|netstat\s+-|ipconfig\s*/all)\b|(?:^|[\s|&`(]|\$\()(?:wget|curl|fetch|lwp-download)\s+(?:-\S{1,10}\s){0,5}(?:https?|ftp)://|(?:^|[\s|&`(]|\$\()(?:nc|ncat|netcat|socat)\s+(?:-\S{1,10}\s){0,5}\S+\s+\d{2,5}\b|(?:^|[\s|&`(]|\$\()(?:bash|sh)\s+-i\b|(?:^|[\s|&`(]|\$\()rm\s+-[rf]{1,2}\s+/|(?:^|[\s|&`(]|\$\()chmod\s+[0-7+]{1,4}[xs]?\s+/'));
$rules[] = rule('WAF-RCE-005', 'Windows-Befehle', 'Erkennt typische Windows-Befehlsketten.', 'critical', 1, 504, $rc, $T,
    anyRegex(['args.*'], '(?:[;|&`]|^)\s*(?:cmd(?:\.exe)?|powershell(?:\.exe)?|wmic|certutil(?:\.exe)?|bitsadmin|mshta|rundll32|regsvr32|cscript|wscript|net\s+(?:user|localgroup|share|view)|reg\s+(?:add|query|delete)|schtasks|vssadmin|whoami|ipconfig|tasklist|systeminfo)\b(?:\.exe)?\s*(?:/|-|\s|$)|%(?:comspec|systemroot|windir|programfiles|appdata|temp|userprofile|computername|username)%'));
$rules[] = rule('WAF-RCE-006', 'Shellshock', 'Erkennt die Shellshock-Signatur () { :; }.', 'critical', 1, 505, $rc, $T,
    anyRegex(['args.*', 'header.*', 'cookie.*'], '\(\s*\)\s*\{\s*:?\s*;?\s*\}\s*;'));
$rules[] = rule('WAF-RCE-007', 'Unix-Befehlsverkettung (breit)', 'Erkennt einfache & gefolgt von Befehlen (Paranoia 2).', 'warning', 2, 510, $rc, $T,
    anyRegex(['args.*'], '&\s*(?:'.$cmds.')\b\s*(?:-|/|\$|\s*$)'));

// ---------------------------------------------------------------- PHP
$ph = ['php', 'owasp-a03'];
$rules[] = rule('WAF-PHP-001', 'PHP-Code-Tag', 'Erkennt <?php und <?= in Parametern.', 'critical', 1, 600, $ph, $T,
    anyRegex(['args.*', 'cookie.*', 'header.user-agent', 'file.name'], '<\?(?:php\b|=)|<\?\s*(?:echo|system|eval|exec|passthru|print|include|require|\$_)|\[\?php'));
$rules[] = rule('WAF-PHP-002', 'Serialisiertes PHP-Objekt', 'Erkennt O:n:"Klasse":-Muster (Object Injection).', 'critical', 1, 601, $ph, ['urlDecodeUni', 'base64DecodeIfValid', 'removeNulls', 'lowercase'],
    anyRegex(['args.*', 'cookie.*', 'raw_body'], '(?:^|[;{}:\s"\'])[oc]:\+?\d+:"[a-z0-9_\\\\\x7f-\xff]+":\+?\d+:\{|(?:^|[;{])a:\d+:\{(?:[isbdo]:\d*:?[^;]*;){0,6}[oc]:\d+:"'));
$rules[] = rule('WAF-PHP-003', 'Gefährliche PHP-Funktionen', 'Erkennt eval(, assert(, system(, shell_exec( u. Ä.', 'critical', 1, 602, $ph, [...$T, 'removeComments'],
    anyRegex(['args.*', 'cookie.*', 'header.user-agent'], '(?<![.\w>$:])(?:eval|assert|system|shell_exec|passthru|popen|proc_open|pcntl_exec|create_function|phpinfo|show_source|highlight_file|php_uname|base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|file_put_contents|move_uploaded_file|call_user_func(?:_array)?|array_map|usort|preg_replace|ob_start|register_shutdown_function|getenv|putenv|ini_set|dl|symlink|posix_\w+|escapeshellcmd|unserialize)\s*\(\s*(?:\$|[\'"`]|@|\(|base64|gz|str_rot|chr\s*\(|\w+\s*\()'));
$rules[] = rule('WAF-PHP-004', 'PHP-Superglobale und Variablenfunktionen', 'Erkennt $_GET/$_POST/$_SERVER-Zugriffe und ${…}-Konstrukte.', 'error', 1, 603, $ph, $T,
    anyRegex(['args.*', 'cookie.*'], '\$_(?:get|post|request|cookie|server|files|env|session)\s*\[|\$\{\s*@?\$?_?\w+\s*\(|\$\w+\s*\(\s*\$_|\$globals\s*\[|\b(?:include|require)(?:_once)?\s*\(?\s*[\'"](?:php|https?|ftp|data|zip|phar|expect)://'));
$rules[] = rule('WAF-PHP-005', 'PHP-Funktionen (breit)', 'Erkennt weitere PHP-Funktionsaufrufe (Paranoia 2).', 'warning', 2, 610, $ph, $T,
    anyRegex(['args.*'], '(?<![.\w>$:])(?:exec|fopen|fwrite|file_get_contents|readfile|include|include_once|require_once|mail|chr|ord|curl_exec|fsockopen|stream_socket_client|copy|rename|unlink|mkdir|chmod)\s*\('));
$rules[] = rule('WAF-PHP-006', 'PHP-Kurzschreibweise', 'Erkennt <? ohne xml (Paranoia 2).', 'warning', 2, 611, $ph, $T,
    anyRegex(['args.*'], '<\?(?!xml\b)'));

// ---------------------------------------------------------------- SSRF
$ss = ['ssrf', 'owasp-a10'];
$internalHost = '(?:localhost|127(?:\.\d{1,3}){3}|0(?:\.0){0,3}|0x7f[0-9a-f.]*|0177[0-7.]*|2130706433|10(?:\.\d{1,3}){3}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|192\.168(?:\.\d{1,3}){2}|169\.254(?:\.\d{1,3}){2}|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])(?:\.\d{1,3}){2}|\[[0-9a-f:.]*\]|[\w.-]*\.(?:local|internal|localhost|localdomain|intranet|corp|lan)|metadata(?:\.google\.internal)?|instance-data|[\w.-]*(?:\.nip\.io|\.xip\.io|\.sslip\.io|localtest\.me|lvh\.me|vcap\.me))';
$rules[] = rule('WAF-SSRF-001', 'SSRF auf interne Adressen', 'Erkennt URLs auf Loopback, RFC 1918, Link-Local und interne Hostnamen.', 'critical', 1, 700, $ss, $T,
    anyRegex(['args.*'], '(?:^|[\s"\'=])(?:https?|ftps?|gopher|dict|ldaps?|tftp|jar|netdoc|ws|wss|sftp|smb|rtsp)://(?:[^/@\s?#]*@)?'.$internalHost.'(?=[:/?#\s"\'\\\\]|$)'));
$rules[] = rule('WAF-SSRF-002', 'Cloud-Metadaten-Endpunkt', 'Erkennt 169.254.169.254, metadata.google.internal, 100.100.100.200 u. Ä.', 'critical', 1, 701, $ss, $T,
    anyRegex(['args.*', 'header.*'], '\b169\.254\.169\.254\b|\bmetadata\.google\.internal\b|\b100\.100\.100\.200\b|\bfd00:ec2::254\b|\b169\.254\.170\.2\b|/latest/meta-data\b|/computemetadata/v1\b|/metadata/instance\b|\b0xa9fea9fe\b|\b2852039166\b'));
$rules[] = rule('WAF-SSRF-003', 'Gefährliche URL-Schemata', 'Erkennt gopher://, dict://, ldap://, tftp://, jar://, file:// u. Ä.', 'critical', 1, 702, $ss, $T,
    anyRegex(['args.*'], '\b(?:gopher|dict|ldaps?|tftp|jar|netdoc|sftp|file|smb|mailto:.*%0a)://|\bfile:/{1,3}\w'));
$rules[] = rule('WAF-SSRF-004', 'IP-Verschleierung', 'Erkennt Dezimal-, Hex- und Oktal-IP-Schreibweisen in URLs.', 'critical', 1, 703, $ss, $T,
    anyRegex(['args.*'], '(?:https?|ftp|gopher|dict)://(?:[^/@\s]*@)?(?:0x[0-9a-f]{6,8}|\d{8,10}|0[0-7]{2,3}(?:\.[0-7]{1,4}){0,3}|0x[0-9a-f]{1,2}(?:\.0x[0-9a-f]{1,2}){1,3}|\d{1,3}\.\d{5,8}|\d{1,3}\.\d{1,3}\.\d{4,5}|\[::(?:ffff:)?[0-9a-f.:]*\]|\[0*:[0:]*:?1?\]|①|⑦)(?=[:/?#\s]|$)'));
$rules[] = rule('WAF-SSRF-005', 'Interne IP im Parameter', 'Erkennt nackte interne IP-Adressen mit Port (Paranoia 2).', 'warning', 2, 710, $ss, $T,
    anyRegex(['args.*'], '^\s*(?:127(?:\.\d{1,3}){3}|10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|localhost):\d{2,5}\b'));

// ---------------------------------------------------------------- XXE
$xe = ['xxe', 'owasp-a05'];
$rules[] = rule('WAF-XXE-001', 'XML External Entity', 'Erkennt <!ENTITY … SYSTEM/PUBLIC in DOCTYPE-Deklarationen.', 'critical', 1, 800, $xe, ['urlDecodeUni', 'htmlEntityDecode', 'removeNulls', 'lowercase', 'compressWhitespace'],
    anyRegex(['args.*', 'raw_body'], '<!entity\s+(?:%\s*)?[\w.-]+\s+(?:system|public)\b|<!entity\s+%|<!doctype\s+\w+\s+(?:system|public)\s+["\'](?:https?|file|ftp|php|expect|jar|netdoc|gopher|data):'));
$rules[] = rule('WAF-XXE-002', 'XInclude und externe DTD', 'Erkennt xi:include und xmlns:xi-Deklarationen.', 'critical', 1, 801, $xe, ['urlDecodeUni', 'htmlEntityDecode', 'removeNulls', 'lowercase'],
    anyRegex(['args.*', 'raw_body'], '<\s*xi:include\b|xmlns:xi\s*=\s*["\']http://www\.w3\.org/2001/xinclude|<!doctype[^>]*\[\s*<!entity|<\s*xsl:(?:value-of|copy-of)\s+select\s*=\s*["\'](?:document|system-property|unparsed-text)\s*\('));
$rules[] = rule('WAF-XXE-003', 'DOCTYPE mit internem Subset', 'Erkennt DOCTYPE mit Entity-Deklarationen (Paranoia 2).', 'warning', 2, 810, $xe, ['urlDecodeUni', 'removeNulls', 'lowercase'],
    anyRegex(['args.*', 'raw_body'], '<!doctype[^>]*\[|<!entity\b'));

// ---------------------------------------------------------------- NoSQL
$ns = ['nosql', 'owasp-a03'];
$ops = 'ne|eq|gt|gte|lt|lte|in|nin|regex|where|exists|or|and|not|nor|expr|elemmatch|all|size|type|mod|text|function|accumulator|jsonschema|lookup|function|comment|natural';
$rules[] = rule('WAF-NOSQL-001', 'NoSQL-Operator als Parametername', 'Erkennt MongoDB-Operatoren ($ne, $gt, $where, …) als Schlüssel.', 'critical', 1, 900, $ns, ['urlDecodeUni', 'lowercase'],
    anyRegex(['args_names', 'cookie_names'], '^\$(?:'.$ops.')$'));
$rules[] = rule('WAF-NOSQL-002', 'NoSQL-Operator im Wert', 'Erkennt {"$ne": …}-Fragmente und $where-JavaScript in Werten.', 'critical', 1, 901, $ns, $T,
    anyRegex(['args.*', 'cookie.*'], '["\']?\$(?:'.$ops.')["\']?\s*:|\[\s*\$(?:'.$ops.')\s*\]|\$where\b.{0,50}(?:function|this\.|sleep|return)'));
$rules[] = rule('WAF-NOSQL-003', 'Server-seitiges JavaScript', 'Erkennt JavaScript-Ausbrüche in NoSQL-Abfragen (\'; return true; …).', 'critical', 1, 902, $ns, $T,
    anyRegex(['args.*'], '[\'"]\s*;\s*return\s+(?:true|1|this|\w+\s*[=!]=)|[\'"]\s*(?:\|\||&&)\s*(?:this\.\w+|[\'"]?\d|true)\s*(?:[=!]=|$|[\'"]?\s*(?:\|\||&&))|\bthis\.\w+\s*(?:[=!]=|\.match\s*\(|\.constructor)|\bdb\.\w+\.(?:find|drop|insert|remove|update)\w*\s*\(|\bsleep\s*\(\s*\d{3,}\s*\)|\bmapreduce\b|\btojson\s*\(|\bobject\.keys\s*\(\s*this'));

// ---------------------------------------------------------------- Protokoll (Regelteil; weitere Prüfungen im Grenzen-Stage)
$pr = ['protocol'];
$rules[] = rule('WAF-PROTO-020', 'CRLF-Injektion (Response Splitting)', 'Erkennt Zeilenumbrüche mit nachfolgendem Header in Parametern.', 'critical', 1, 60, $pr, ['urlDecodeUni', 'lowercase'],
    anyRegex(['args.*', 'uri'], '[\r\n]+\s*(?:set-cookie|location|content-(?:type|length|disposition)|x-[\w-]+|refresh|access-control-[\w-]+|http/\d)\s*:|%0d%0a|\\\\r\\\\n\s*(?:set-cookie|location)'));
$rules[] = rule('WAF-PROTO-021', 'Ungültige Zeichen im Pfad', 'Erkennt Steuerzeichen im Pfad.', 'error', 1, 61, $pr, ['urlDecodeUni'],
    anyRegex(['path'], '[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]'));
$rules[] = rule('WAF-PROTO-022', 'HTTP Request Smuggling', 'Erkennt verschachtelte HTTP-Anfragen in Parametern oder im Body.', 'critical', 1, 62, $pr, ['urlDecodeUni', 'lowercase'],
    anyRegex(['args.*', 'raw_body'], '(?:^|[\r\n])(?:get|post|put|delete|head|options|patch)\s+/\S*\s+http/\d\.\d[\r\n]'));

// ---------------------------------------------------------------- JNDI
$jn = ['jndi', 'log4shell', 'owasp-a06'];
$rules[] = rule('WAF-JNDI-001', 'Log4Shell / JNDI-Lookup', 'Erkennt ${jndi:…} inkl. verschachtelter Lookups (${${lower:j}ndi:…}).', 'critical', 1, 50, $jn, ['urlDecodeUni', 'htmlEntityDecode', 'jsDecode', 'utf8Normalize', 'removeNulls', 'lowercase', 'removeWhitespace'],
    anyRegex(['args.*', 'args_names', 'header.*', 'cookie.*', 'path', 'uri'], '\$\{[^}]{0,60}?(?:jndi|ldaps?|rmi|dns|iiop|nis|nds|corba)[^}]{0,10}?:|\$\{\$\{|\$\{(?:lower|upper|env|sys|date|java|base64|main|bundle|k8s|docker|web|spring|log4j|ctx|marker|jvmrunargs|sd|map|event):|\$\{::-'));
$rules[] = rule('WAF-JNDI-002', 'JNDI-Protokoll-URL', 'Erkennt jndi:ldap:// und ähnliche Ziel-URLs ohne Lookup-Hülle.', 'critical', 1, 51, $jn, ['urlDecodeUni', 'lowercase', 'removeWhitespace'],
    anyRegex(['args.*', 'header.*', 'cookie.*'], '\bjndi:(?:ldaps?|rmi|dns|iiop|nis|nds|corba|https?)://'));

// ---------------------------------------------------------------- Prototype Pollution
$pp = ['prototype-pollution'];
$rules[] = rule('WAF-PPOL-001', 'Prototype Pollution (__proto__)', 'Erkennt __proto__ als Schlüssel oder in Parameternamen.', 'critical', 1, 950, $pp, ['urlDecodeUni', 'lowercase'],
    ['match' => 'any', 'items' => [
        ['target' => 'args_names', 'operator' => 'regex', 'value' => '__proto__'],
        ['target' => 'uri', 'operator' => 'regex', 'value' => '__proto__'],
        ['target' => 'raw_body', 'operator' => 'regex', 'value' => '["\']__proto__["\']\s*:'],
        ['target' => 'args.*', 'operator' => 'regex', 'value' => '["\']__proto__["\']\s*:|\[\s*["\']?__proto__["\']?\s*\]|\.__proto__\.'],
    ]]);
$rules[] = rule('WAF-PPOL-002', 'Prototype Pollution (constructor.prototype)', 'Erkennt constructor.prototype als Schlüsselpfad.', 'critical', 1, 951, $pp, ['urlDecodeUni', 'lowercase'],
    ['match' => 'any', 'items' => [
        ['target' => 'uri', 'operator' => 'regex', 'value' => 'constructor(?:\]?\[|\.)\s*["\']?prototype'],
        ['target' => 'args.*', 'operator' => 'regex', 'value' => 'constructor(?:\]?\[|\.)\s*["\']?prototype|["\']constructor["\']\s*:\s*\{\s*["\']prototype["\']'],
        ['target' => 'raw_body', 'operator' => 'regex', 'value' => '["\']constructor["\']\s*:\s*\{\s*["\']prototype["\']'],
        ['target' => 'args_names', 'operator' => 'regex', 'value' => '^prototype$'],
    ]]);

// ---------------------------------------------------------------- Scanner / Recon
$sc = ['scanner', 'recon'];
$rules[] = rule('WAF-SCAN-001', 'Zugriff auf versteckte Konfigurationsdateien', 'Erkennt Zugriffe auf /.env, /.git/, /.svn/, /.htaccess u. Ä.', 'critical', 1, 20, $sc, $TP,
    anyRegex(['path'], '/\.(?:env|git|svn|hg|bzr|cvs|ds_store|htaccess|htpasswd|idea|vscode|aws|docker|npmrc|yarnrc|ssh|bash_history|zsh_history|mysql_history|pgpass|netrc|travis\.yml|gitlab-ci\.yml|circleci|kube|composer|config|sql|history|vagrant|terraform|well-known/(?:\.\.|%2e))(?:[/.\-_~]|$)|/(?:\.env|env)\.(?:bak|old|save|swp|backup|orig|dist|local|prod|production|dev|example|sample|txt|tmp)$'));
$rules[] = rule('WAF-SCAN-002', 'Zugriff auf typische Admin-/CMS-Pfade', 'Erkennt /wp-admin, /phpmyadmin, /adminer.php, /cgi-bin u. Ä. (Laravel-Anwendung).', 'error', 1, 21, $sc, $TP,
    anyRegex(['path'], '^/(?:wp-(?:admin|content|includes|json|login\.php|config\.php|cron\.php|signup\.php|trackback\.php)|xmlrpc\.php|wordpress/|wp/|blog/wp-|phpmyadmin|phpmyadmin\d*|pma|myadmin|mysqladmin|sqladmin|dbadmin|adminer(?:-[\d.]+)?(?:\.php)?|phpinfo\.php|info\.php|php-info\.php|test\.php|i\.php|shell\.php|cmd\.php|c99\.php|r57\.php|webshell|server-status|server-info|cgi-bin/|cgi/|scripts/|actuator(?:/|$)|_profiler/phpinfo|elmah\.axd|trace\.axd|jmx-console|web-console|invoker/|manager/html|admin\.php|administrator/(?:index\.php|$)|joomla|drupal|magento|typo3/|umbraco|owa/|ecp/|autodiscover/autodiscover\.xml|boaform/|hnap1|goform/|setup\.cgi|sitecore|solr/admin|druid/|nacos/|struts|axis2|vpn/|remote/login|dana-na/|global-protect|cgi-mod/|mifs/|\+cscoe\+)'));
$rules[] = rule('WAF-SCAN-003', 'Bekannte Laravel-/PHP-Exploit-Pfade', 'Erkennt /vendor/phpunit, /_ignition/execute-solution, /storage/logs u. Ä.', 'critical', 1, 22, $sc, $TP,
    anyRegex(['path'], '/vendor/(?:phpunit|.*eval-stdin\.php)|/eval-stdin\.php|/_ignition/(?:execute-solution|health-check|scripts)|/storage/(?:logs|framework)/|/(?:bootstrap/cache|app/(?:config|http))/|/(?:composer|package|package-lock|yarn\.lock|phpunit|docker-compose|dockerfile|webpack\.mix|artisan|server)\.(?:json|lock|xml|ya?ml|js|php)?$|^/(?:artisan|composer\.(?:json|lock)|\.php_cs|phpunit\.xml(?:\.dist)?)$|/telescope/requests|/horizon/api/'));
$rules[] = rule('WAF-SCAN-004', 'Backup- und Dump-Dateien', 'Erkennt Zugriffe auf .bak, .sql, .old, ~-Dateien u. Ä.', 'error', 1, 23, $sc, $TP,
    anyRegex(['path'], '\.(?:bak|backup|old|orig|save|swp|swo|sav|tmp|temp|copy|dist|sql|sqlite3?|db|mdb|dump|tar|tar\.gz|tgz|gz|zip|rar|7z|bz2|war|jar|log|ini|conf|cfg|inc|pem|key|crt|p12|pfx|kdbx|ovpn|rdp)$|~$|/(?:backup|backups|dump|dumps|db|database|sql|site|www|htdocs|public_html|old|bak)(?:/|\.)|#$|/core\.\d+$'));
$rules[] = rule('WAF-SCAN-005', 'Scanner-User-Agent', 'Erkennt bekannte Schwachstellen-Scanner (sqlmap, nikto, nuclei, …).', 'critical', 1, 10, $sc, ['lowercase'],
    anyRegex(['user_agent'], '\b(?:sqlmap|nikto|nuclei|acunetix|nessus|openvas|w3af|wpscan|dirbuster|gobuster|ffuf|feroxbuster|wfuzz|masscan|zgrab|nmap|havij|netsparker|appscan|burpsuite|burp collaborator|owasp zap|zaproxy|qualys|jaeles|xsstrike|commix|whatweb|fimap|joomscan|droopescan|arachni|skipfish|projectdiscovery|interactsh|dirsearch|hydra|medusa|metasploit|morfeus|zmeu|jorgee|paros|webinspect|vega/|grabber|bsqlbf|pangolin|sqlninja|absinthe|brutus|nsauditor|webshag|cgichk|gootkit|x-scan|wapiti|uniscan|ldapsearch|httprobe|fuzz faster|python-xsstrike|struts-pwn|log4j-scan|zmap|censys|shodan)\b'));
$rules[] = rule('WAF-SCAN-006', 'Scanner-Header', 'Erkennt typische Header von Scannern (X-Scanner, Acunetix-Aspect, …).', 'critical', 1, 11, $sc, ['lowercase'],
    ['match' => 'any', 'items' => [
        ['target' => 'header.x-scanner', 'operator' => 'exists'],
        ['target' => 'header.acunetix-aspect', 'operator' => 'exists'],
        ['target' => 'header.x-wipp', 'operator' => 'exists'],
        ['target' => 'header.x-request-memo', 'operator' => 'exists'],
        ['target' => 'header.x-scan-memo', 'operator' => 'exists'],
        ['target' => 'header.x-nuclei', 'operator' => 'exists'],
    ]]);

// ---------------------------------------------------------------- Bots (User-Agent)
$bt = ['bot'];
$rules[] = rule('WAF-BOT-001', 'Leerer User-Agent', 'Request ohne User-Agent-Header.', 'notice', 1, 30, $bt, [],
    anyRegex(['user_agent'], '^\s*$'));
$rules[] = rule('WAF-BOT-002', 'Bibliotheks-User-Agent', 'HTTP-Bibliotheken (python-requests, curl, Go-http-client, …) – nur Score, kein Block (APIs!).', 'notice', 1, 31, $bt, ['lowercase'],
    anyRegex(['user_agent'], '^(?:python-requests|python-urllib|python-httpx|aiohttp|curl|wget|go-http-client|libwww-perl|lwp::simple|java/|apache-httpclient|okhttp|axios|node-fetch|undici|got \(|scrapy|httpclient|php/|guzzlehttp|ruby|faraday|winhttp|powershell|httpie|insomnia|postmanruntime)', ), ['type' => 'score', 'points' => 2]);
$rules[] = rule('WAF-BOT-003', 'Bekannte Bad-Bots', 'Erkennt aggressive Crawler und Spam-Bots.', 'warning', 1, 32, $bt, ['lowercase'],
    anyRegex(['user_agent'], '\b(?:mj12bot|dotbot|semrushbot|ahrefsbot|blexbot|petalbot|megaindex|seekport|serpstatbot|dataforseobot|zoominfobot|bytespider|claudebot-fake|emailcollector|emailsiphon|webzip|webcopier|httrack|teleport|offline explorer|sitesnagger|extractorpro|harvest|grub|larbin|nutch|pycurl|masscan|zgrab)\b'));

// ---------------------------------------------------------------- Response-Leaks (Phase response)
$lk = ['leak', 'owasp-a05'];
$rules[] = rule('WAF-LEAK-001', 'Stacktrace in Antwort', 'Erkennt PHP-/Laravel-Stacktraces in der Antwort.', 'error', 1, 100, $lk, [],
    anyRegex(['raw_body'], '(?:Stack trace:\s*#0 |#\d+ /[\w/.\-]+\.php\(\d+\): |Whoops, looks like something went wrong|Symfony\\\\Component\\\\ErrorHandler|Illuminate\\\\[A-Za-z\\\\]+Exception|PHP (?:Fatal|Parse) error:|<b>(?:Fatal|Parse) error</b>:|Uncaught (?:Exception|Error|TypeError))'), ['type' => 'log'], 'response');
$rules[] = rule('WAF-LEAK-002', 'SQL-Fehlermeldung in Antwort', 'Erkennt SQL-Fehlermeldungen (MySQL, MariaDB, PostgreSQL, SQLite, MSSQL).', 'error', 1, 101, $lk, [],
    anyRegex(['raw_body'], '(?:SQLSTATE\[\w+\]|You have an error in your SQL syntax|mysqli?_(?:fetch|query|num_rows)|Warning: pg_|PostgreSQL query failed|ORA-\d{5}|Microsoft OLE DB Provider for SQL Server|Unclosed quotation mark after the character string|SQLite3?::|near ".{1,40}": syntax error|MariaDB server version for the right syntax)'), ['type' => 'log'], 'response');
$rules[] = rule('WAF-LEAK-003', 'Serverpfade in Antwort', 'Erkennt absolute Serverpfade (/var/www/, /home/…/public_html).', 'warning', 1, 102, $lk, [],
    anyRegex(['raw_body'], '(?:/var/www/[\w.\-/]+\.php|/home/[\w.\-]+/(?:public_html|www|htdocs|web)/[\w.\-/]+\.php|/srv/(?:www|http)/[\w.\-/]+\.php|[A-Z]:\\\\(?:inetpub|xampp|wamp)\\\\)'), ['type' => 'log'], 'response');
$rules[] = rule('WAF-LEAK-004', '.env-Inhalte in Antwort', 'Erkennt typische .env-Zeilen (APP_KEY=, DB_PASSWORD=).', 'critical', 1, 103, $lk, [],
    anyRegex(['raw_body'], '(?:^|\n)\s*(?:APP_KEY=base64:|DB_PASSWORD=|AWS_SECRET_ACCESS_KEY=|MAIL_PASSWORD=|REDIS_PASSWORD=|WAF_PEPPER=|STRIPE_SECRET=)'), ['type' => 'log'], 'response');
$rules[] = rule('WAF-LEAK-005', 'Privater Schlüssel in Antwort', 'Erkennt -----BEGIN … PRIVATE KEY-----.', 'critical', 1, 104, $lk, [],
    anyRegex(['raw_body'], '-----BEGIN (?:RSA |DSA |EC |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----'), ['type' => 'log'], 'response');

$pack = [
    'schema' => 'waf-rulepack/1',
    'pack' => 'core',
    'version' => '1.0.0',
    'description' => 'Mitgelieferte Kernregeln der Laravel-WAF (angelehnt an OWASP CRS).',
    'rules' => $rules,
];

$json = json_encode($pack, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
file_put_contents(__DIR__.'/../resources/rules/core-v1.json', $json."\n");
fwrite(STDOUT, count($rules)." Regeln geschrieben.\n");
