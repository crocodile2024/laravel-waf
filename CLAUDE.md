# CLAUDE.md — WAF – WebApplicationFirewall (Laravel-Paket)

Composer-Paket `crocodile2024/laravel-waf`, das jede Laravel-13-Anwendung mit einer anwendungsseitigen Web Application Firewall inklusive Verwaltungsoberfläche ausstattet. Vollständig self-hosted, DSGVO-konform, kein Datenabfluss an Dritte, clustertauglich (mehrere App-Server hinter Hetzner Load Balancer / ISPConfig-Reverse-Proxy).

---

## 1. Grundsätze

- **Zielplattform:** Laravel 13, PHP 8.4, MariaDB (Galera-tauglich), Redis.
- **`declare(strict_types=1);`** in jeder PHP-Datei.
- **UI-Texte immer Deutsch**, Code-Bezeichner Englisch.
- **Keine externen Aufrufe zur Laufzeit.** Kein CDN, kein reCAPTCHA/hCaptcha/Turnstile, keine Cloud-GeoIP, keine Telemetrie. Einzige Ausnahme: der explizit vom Admin ausgelöste Befehl `waf:geoip:update`.
- **Nicht verwenden:** Tailwind, jQuery, Livewire, Inertia, Filament, Docker, CDN-Assets.
- **UI-Stack:** Blade, Bootstrap 5.3 (lokal via Sass/Vite kompiliert), Alpine.js (CSP-Build), Bootstrap Icons, Chart.js (gebündelt). Alle Assets und Schriften lokal.
- **Designsystem:** Hintergrund Off-White `#f5f4f0`, Primärfarbe Indigo `#4f46e5`, Headlines *Instrument Serif*, Fließtext *Plus Jakarta Sans*, Code/Payloads *JetBrains Mono*.
- **Architektur:** Controller dünn, gesamte Logik in Services. Reihenfolge je Feature strikt: **Migration → Model → Policy → Service → FormRequest → Controller → Views**.
- **Performance-Budget:** Die WAF-Middleware darf bei einem typischen Request (≤ 20 Parameter, ≤ 16 KB Body) **p95 ≤ 2 ms** zusätzliche Latenz verursachen. Keine DB-Abfrage im Hot-Path – Konfiguration und Regeln kommen kompiliert aus Redis bzw. APCu-ähnlichem In-Process-Cache.
- **Fail-Verhalten konfigurierbar:** Fällt Redis aus, gilt `fail_mode` (`open` = durchlassen + loggen, `closed` = 503). Standard: `open`.

---

## 2. Paketstruktur

```
laravel-waf/
├── composer.json
├── config/waf.php
├── database/migrations/
├── resources/
│   ├── views/                 # Blade-UI + Block-/Challenge-Seiten
│   ├── lang/de/waf.php
│   ├── sass/waf.scss
│   ├── js/waf.js              # Alpine-CSP-Komponenten, Chart.js
│   └── rules/                 # Mitgelieferte Regelpakete (JSON, versioniert)
├── dist/                      # Vorkompilierte Assets (im Repo committet)
├── routes/waf.php
├── src/
│   ├── WAFServiceProvider.php
│   ├── Http/
│   │   ├── Middleware/        # Firewall, SecurityHeaders, ResponseInspector
│   │   ├── Controllers/       # UI- und Challenge-Controller
│   │   └── Requests/
│   ├── Engine/
│   │   ├── Inspector.php      # Orchestriert alle Prüfungen
│   │   ├── RequestContext.php # Unveränderliches Abbild des Requests
│   │   ├── Normalizer/        # Transformationen
│   │   ├── Detectors/         # SQLi, XSS, LFI, RCE, …
│   │   ├── Rules/             # Regel-DSL, Compiler, Matcher
│   │   └── Scoring/           # Anomalie-Score, Paranoia-Level
│   ├── Services/              # IpListService, BanService, RateLimitService, …
│   ├── Models/
│   ├── Policies/
│   ├── Events/
│   ├── Listeners/
│   ├── Notifications/
│   ├── Console/Commands/
│   └── Support/               # IpMatcher (CIDR v4/v6), Anonymizer, Redactor
└── tests/                     # Pest + Orchestra Testbench
```

**Assets:** Das Paket wird mit vorkompilierten Assets in `dist/` ausgeliefert, weil die Host-App sie nicht bauen muss. `php artisan vendor:publish --tag=waf-assets` kopiert sie nach `public/vendor/waf/`. Paketintern Build via Vite (`npm run build`), Ausgabe mit Hash im Dateinamen und Manifest.

**composer.json:**
- `require`: `php: ^8.4`, `laravel/framework: ^13.0`, `ext-redis` oder `predis/predis` (eines von beiden), `geoip2/geoip2` (lokale MMDB-Abfrage).
- `require-dev`: `orchestra/testbench`, `pestphp/pest`, `larastan/larastan`, `laravel/pint`.
- `suggest`: `ext-apcu` (In-Process-Cache), ClamAV-Daemon (Upload-Scan).
- Auto-Discovery über `extra.laravel.providers`.

Namespace: `Crocodile2024\WAF`.

---

## 3. Installation & Einbindung

```bash
composer require crocodile2024/laravel-waf
php artisan waf:install        # publiziert Config, Assets, Migrationen; migriert; legt Standardregeln an
```

- Die Middleware `Crocodile2024\WAF\Http\Middleware\Firewall` wird vom ServiceProvider **an den Anfang** der globalen Middleware-Kette gehängt (`$middleware->prepend()`), nach `TrustProxies`.
- Zusätzlich verfügbar als Alias `waf` und `waf:profile,<name>` für routenspezifische Profile (z. B. strenger für `/login`, lockerer für `/api/webhooks`).
- `SecurityHeaders` und `ResponseInspector` werden global angehängt (`append`), sofern in der Config aktiv.
- `waf:install` prüft und warnt, wenn `TrustProxies` nicht konfiguriert ist (ohne korrekte Client-IP ist die WAF wirkungslos).

---

## 4. Betriebsmodi

| Modus | Verhalten |
|---|---|
| `off` | WAF komplett deaktiviert (nur Security-Header bleiben, falls aktiv) |
| `learning` | Nichts wird blockiert; Treffer werden geloggt **und** als Ausnahme-Vorschläge gesammelt |
| `detect` | Nichts wird blockiert; Treffer werden geloggt und gemeldet |
| `block` | Regelaktionen werden durchgesetzt |

Der Modus ist global sowie **pro Regel** und **pro Profil** überschreibbar (z. B. neue Regel zunächst `detect`, global `block`).

---

## 5. Funktionsumfang

### 5.1 Request-Normalisierung

Vor der Erkennung wird jeder Prüfwert über eine Transformationskette normalisiert (pro Regel wählbar):
`urlDecodeUni` (mehrfach, max. 3 Runden), `htmlEntityDecode`, `lowercase`, `removeNulls`, `compressWhitespace`, `removeComments` (SQL/HTML), `normalizePath` (`../`, `//`, `\`), `utf8Normalize` (NFKC, Overlong-UTF-8 erkennen), `base64DecodeIfValid`, `jsDecode`, `cssDecode`, `hexDecode`.

**Prüfziele:** Pfad, Query-Parameter (Namen und Werte), Body (Form, JSON rekursiv, XML), Header, Cookies, Methode, Dateinamen von Uploads, Rohbody (optional, begrenzt auf `inspection.max_body_bytes`, Standard 64 KB).

JSON-Bodies werden rekursiv bis Tiefe 32 flachgeklopft (`user.address.street`); tiefere Strukturen erzeugen einen Treffer `WAF-PROTO-002 (Verschachtelung zu tief)`.

### 5.2 Erkennungsmodule (Detectors)

Jedes Modul ist einzeln aktivierbar und hat Regeln mit Paranoia-Level 1–4 (angelehnt an OWASP CRS). Nur Regeln ≤ eingestelltem Level sind aktiv.

| ID-Präfix | Modul | Beispiele |
|---|---|---|
| `WAF-SQLI` | SQL-Injection | `UNION SELECT`, Tautologien, Stacked Queries, `SLEEP()`/`BENCHMARK()`, Kommentar-Obfuskation, libinjection-artige Token-Analyse |
| `WAF-XSS` | Cross-Site-Scripting | `<script`, Event-Handler (`on\w+=`), `javascript:`-URIs, SVG/MathML-Vektoren, `srcdoc`, Template-Injection (`{{`, `${`) |
| `WAF-LFI` | Path Traversal / LFI | `../`, `%2e%2e`, `/etc/passwd`, `php://`, `phar://`, `data://`, `expect://`, `zip://` |
| `WAF-RFI` | Remote File Inclusion | URL-Parameter mit `http(s)://` auf Include-typischen Namen, `?` am Ende |
| `WAF-RCE` | Command Injection | `;`, `|`, `` ` ``, `$(…)`, Shell-Builtins, `/bin/sh`, PowerShell |
| `WAF-PHP` | PHP-spezifisch | `<?php`, serialisierte Objekte `O:\d+:`, gefährliche Funktionen, `eval(`, `assert(` |
| `WAF-SSRF` | Server-Side Request Forgery | Interne IPs (RFC 1918, Loopback, Link-Local, `169.254.169.254`), Dezimal-/Hex-IP-Notation, `gopher://`, `file://` |
| `WAF-XXE` | XML External Entity | `<!DOCTYPE` mit `<!ENTITY … SYSTEM` |
| `WAF-NOSQL` | NoSQL-Injection | `$ne`, `$gt`, `$where` als Schlüssel |
| `WAF-PROTO` | Protokollverstöße | Unzulässige Methode, fehlender Host, CRLF in Headern (Response Splitting), doppelte Content-Length, Header > Limit, Parameteranzahl > Limit |
| `WAF-JNDI` | Log4Shell-artige Muster | `${jndi:`, verschachtelte Lookups |
| `WAF-PPOL` | Prototype Pollution | `__proto__`, `constructor.prototype` als Schlüssel |
| `WAF-SCAN` | Scanner/Recon | Zugriffe auf `/.env`, `/.git/`, `/wp-admin`, `/phpmyadmin`, `/vendor/phpunit`, Backup-Dateien (`.bak`, `.sql`, `~`), bekannte Scanner-User-Agents (sqlmap, nikto, nuclei, …) |
| `WAF-LEAK` | Response-Leaks | (Response-Inspektion, s. 5.11) |

**Mitgelieferte Regeln** liegen als JSON-Regelpakete in `resources/rules/` (`core-v1.json`), werden beim Install/Update in die DB importiert und sind versioniert. Mitgelieferte Regeln sind im UI nicht editierbar, aber deaktivierbar und mit Ausnahmen versehbar. Das Regelpaket-Format ist so gestaltet, dass es auch von der ISPConfig-WAF-Erweiterung gelesen werden kann (gleiches JSON-Schema, s. Anhang A).

### 5.3 Anomalie-Scoring

- Jeder Regeltreffer liefert einen Score nach Schwere: `critical=5`, `error=4`, `warning=3`, `notice=2`.
- Erreicht die Summe eines Requests den **Inbound-Schwellwert** (Standard 5), wird blockiert.
- Regeln können statt Scoring eine **Sofortaktion** haben: `block`, `allow`, `challenge`, `log`, `ban`, `tag`.
- **IP-Reputation-Score:** Scores aller Requests einer IP summieren sich in Redis mit Zerfall (Halbwertszeit konfigurierbar, Standard 1 h). Überschreitet die Reputation den Ban-Schwellwert (Standard 50), wird die IP automatisch gesperrt (5.6).

### 5.4 Eigene Regeln (Regel-Editor)

Admins legen im UI eigene Regeln an — dient auch dem **virtuellen Patchen** bekannter Lücken.

**Bestandteile:**
- Name, Beschreibung, Priorität (0–1000, niedrig = früher), aktiv/inaktiv, Modus-Override.
- **Bedingungen** (verknüpft mit UND/ODER, eine Verschachtelungsebene):
  - Ziel: `path`, `method`, `query.*`/`query.<name>`, `body.*`/`body.<name>`, `header.<name>`, `cookie.<name>`, `ip`, `country`, `asn`, `user_agent`, `route_name`, `authenticated`, `user_id`, `file.extension`, `file.mime`, `file.size`.
  - Operator: `equals`, `contains`, `starts_with`, `ends_with`, `regex`, `in_list`, `ip_in_cidr`, `gt`, `lt`, `exists`, `not_exists`, `length_gt`, `detect_sqli`, `detect_xss` sowie Negation.
  - Transformationen (Liste aus 5.1).
- **Aktion:** `block` (Statuscode wählbar 403/404/429/503), `allow` (überspringt weitere Prüfungen), `challenge`, `log`, `score:+N`, `ban:<Dauer>`, `rate_limit:<Profil>`, `tag:<Name>`.

**Regex-Sicherheit:** Alle Regex werden beim Speichern mit `preg_match` gegen leeren String validiert, `pcre.backtrack_limit` wird während der Prüfung auf 100 000 begrenzt; Regex mit verschachtelten Quantoren (`(a+)+`) werden abgelehnt (ReDoS-Schutz).

**Regel-Tester im UI:** Eingabe eines Beispiel-Requests (Methode, Pfad, Header, Body als Rohtext) → Anzeige aller treffenden Regeln, Score, Ergebnis, Normalisierungsschritte. Gleiche Funktion als `waf:rules:test`.

**Kompilierung:** Regeln werden nach jeder Änderung zu einem PHP-Array-Plan kompiliert, in Redis unter `waf:rules:<version>` abgelegt und die Version per Redis-Pub/Sub an alle Knoten verteilt (6.).

### 5.5 Ausnahmen (False-Positive-Handling)

- Ausnahme = (Regel-ID oder Regel-Tag) × (Route-Name, Pfad-Muster oder global) × optional (Parameter-Name) × optional (IP/CIDR).
- **Aus jedem Ereignis heraus** per Button „Ausnahme anlegen“ mit vorausgefülltem Formular.
- **Learning-Modus:** Gesammelte Treffer werden gruppiert (Regel × Route × Parameter) mit Häufigkeit und Anzahl unterschiedlicher IPs/Benutzer. Liste „Ausnahme-Vorschläge“ mit Massen-Übernahme. Vorschläge mit Treffern von nur einer IP werden als „verdächtig“ markiert und nicht vorausgewählt.
- Ausnahmen haben optional ein Ablaufdatum.

### 5.6 IP-Listen & Sperren

- **Allowlist** (umgeht alle Prüfungen außer Security-Header), **Denylist** (sofort 403).
- Einträge: einzelne IP, CIDR (IPv4/IPv6), Kommentar, Ablaufdatum, Quelle (`manual`, `auto`, `import`, `api`).
- IPv6-Adressen werden für Rate-Limit und Bans standardmäßig auf **/64** aggregiert (konfigurierbar).
- **Auto-Ban** mit Eskalation: 1. Ban 15 min, 2. Ban 1 h, 3. Ban 24 h, ab 4. Ban 7 Tage (konfigurierbar); Zähler verfällt nach 30 Tagen ohne Vorfall.
- Bans liegen in Redis (Hot-Path) **und** DB (Persistenz, UI). Bei Redis-Neustart lädt `waf:sync` aktive Bans aus der DB zurück; zusätzlich beim Boot, falls der Redis-Schlüssel `waf:bans:loaded` fehlt.
- Import/Export als CSV und einfache Textliste (eine IP/CIDR pro Zeile).
- **Abonnierbare Blocklisten** (optional, standardmäßig aus): Admin hinterlegt URLs eigener oder öffentlicher Listen (z. B. FireHOL Level 1); Abruf ausschließlich per Scheduler-Job, nie im Request.

### 5.7 Geo- & ASN-Filter

- Lokale MaxMind-GeoLite2- oder DB-IP-Lite-MMDB-Dateien (Pfad in Config). Keine Online-Abfrage.
- Länder-Allowlist oder -Denylist, global oder pro Profil (z. B. Admin-Bereich nur DE/AT/CH).
- ASN-Denylist (z. B. bekannte Hosting-ASNs für Login-Seiten).
- `waf:geoip:update` lädt die Datenbank mit hinterlegtem Lizenzschlüssel herunter (einziger externer Aufruf, nur manuell oder per Scheduler, wenn vom Admin aktiviert).
- Fehlt die MMDB, sind Geo-Funktionen im UI ausgegraut mit Hinweis.

### 5.8 Rate-Limiting & Missbrauchserkennung

Redis-basiert (Sliding-Window per Sorted Set oder GCRA), clusterweit konsistent.

- **Profile** (im UI anlegbar): Name, Schlüssel (`ip`, `ip+route`, `user`, `ip+user_agent`, `header:<name>`), Limit, Fenster, Burst, Aktion bei Überschreitung (`429`, `challenge`, `ban`, `score:+N`).
- Zuweisung per Route-Pattern, Route-Name, Methode oder Middleware-Parameter `waf:profile,<name>`.
- **Vordefinierte Schutzmechanismen:**
  - **Login-Bruteforce:** Fehlgeschlagene Logins (Event `Illuminate\Auth\Events\Failed`) je IP und je Benutzerkennung; ab Schwelle Challenge, danach Ban. Benutzerkennung wird nur gehasht gespeichert.
  - **404-Flut:** > N 404-Antworten in Zeitfenster → Score/Ban (typisch für Scanner).
  - **Fehler-Flut:** > N 4xx/5xx-Antworten.
  - **Passwort-Reset- und Registrierungs-Missbrauch:** eigenes Profil.
- Standard-Header `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset`, `Retry-After` (abschaltbar).

### 5.9 Bot-Schutz & Challenge

- **User-Agent-Regeln:** leerer UA, bekannte Bad-Bots/Scanner, offensichtliche Bibliotheks-UAs (`python-requests`, `curl`, `Go-http-client`) — Letztere standardmäßig nur `score`, nicht `block` (APIs!).
- **Verifizierte Suchmaschinen-Bots:** Behauptet ein UA Googlebot/Bingbot/Applebot/DuckDuckBot, wird per Reverse-DNS + Forward-Bestätigung geprüft (Ergebnis 24 h in Redis gecacht). Fälschung → Score 5.
- **Challenge (eigene Implementierung, keine Drittanbieter):**
  1. **Proof-of-Work (Standard):** Seite liefert Aufgabe (SHA-256-Präfix mit Schwierigkeit 16–22 Bit, konfigurierbar), Lösung per Web Worker im Browser, Prüfung serverseitig. Barrierearm, kein Rätsel für den Nutzer.
  2. **Bild-Captcha (Fallback ohne JavaScript):** Serverseitig mit GD erzeugt, Zeichen ohne Verwechslungsgefahr, Audio-Alternative entfällt; stattdessen Hinweis auf Kontakt.
  - Nach erfolgreicher Lösung: signiertes, HttpOnly-, Secure-, SameSite=Lax-Cookie `waf_pass` (HMAC über IP-Präfix + UA-Hash + Ablauf, Standard 12 h). Kein personenbezogenes Tracking.
  - Challenge nur für `GET`/`HEAD` mit HTML-Accept; für API-/JSON-Requests stattdessen 429 mit JSON-Fehler.
- **Honeypots:**
  - **Fallen-Routen:** konfigurierbare Pfade (z. B. `/wp-login.php`), Aufruf → sofortiger Ban.
  - **Formular-Honeypot:** Blade-Komponente `<x-waf::honeypot />` fügt verstecktes Feld + Zeitstempel (signiert) ein; ausgefülltes Feld oder Absenden < 2 s → Treffer `WAF-BOT-010`.

### 5.10 Upload-Prüfung

- Erlaubte Erweiterungen und MIME-Typen global und pro Profil.
- Abgleich Erweiterung ↔ tatsächlicher MIME (finfo) ↔ Magic Bytes.
- Erkennung: doppelte Endungen (`bild.php.jpg`), Null-Bytes im Namen, PHP-Tags in Bildern/PDFs, Polyglots, SVG mit Script/Event-Handlern, ZIP-Bomben (Kompressionsrate > 100 bei Archiven).
- Optional **ClamAV** über Unix- oder TCP-Socket (`clamd`, INSTREAM). Timeout 5 s, Verhalten bei Nichterreichbarkeit gemäß `fail_mode`.
- Maximale Dateigröße und -anzahl pro Request.

### 5.11 Response-Härtung & -Inspektion

**Security-Header-Middleware** (alles einzeln schaltbar, Werte im UI editierbar):
- `Content-Security-Policy` mit **Nonce pro Request** (Blade-Direktive `@wafNonce`, Helper `waf_nonce()`), Report-Only-Modus, eigener Report-Endpunkt `POST /waf/csp-report` → CSP-Verstöße erscheinen im UI.
- `Strict-Transport-Security` (max-age, includeSubDomains, preload), `X-Content-Type-Options: nosniff`, `X-Frame-Options`/`frame-ancestors`, `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`.
- Entfernen von `X-Powered-By` und `Server`-Details.
- Cookies: erzwingt `Secure`, `HttpOnly` (außer Allowlist), `SameSite` gemäß Config.

**Response-Inspektion** (optional, Standard aus, nur für `text/html` und `application/json` bis 512 KB):
- Erkennung von Stacktraces, SQL-Fehlermeldungen, Pfaden (`/var/www/`), `.env`-Inhalten, privaten Schlüsseln (`-----BEGIN … PRIVATE KEY-----`).
- Aktion: `log` oder Ersatz durch generische 500-Seite.

### 5.12 Request-Grenzen

Konfigurierbar global und pro Profil: erlaubte Methoden, max. URL-Länge (Standard 4096), max. Header-Größe (8 KB) und -Anzahl (100), max. Parameteranzahl (500), max. Parameterlänge (64 KB), max. Body-Größe, erlaubte Content-Types, Pflicht-Host-Header gegen Allowlist (Host-Header-Injection).

### 5.13 Block- und Challenge-Seiten

- Eigene Blade-Seiten im Designsystem, Deutsch, publizierbar (`--tag=waf-views`) zum Anpassen.
- Inhalt: verständliche Erklärung, **Vorfall-ID** (ULID), Uhrzeit, Hinweis „Falls Sie glauben, dass es sich um einen Fehler handelt, nennen Sie bitte die Vorfall-ID“, optional Kontaktadresse aus Config.
- **Keine** Angabe der Regel oder des Grundes (keine Information für Angreifer).
- JSON-Requests erhalten `{"error":"request_blocked","incident_id":"…"}` mit passendem Statuscode.

### 5.14 Integration in die Host-App

- **Events:** `RequestBlocked`, `RequestChallenged`, `ChallengePassed`, `IpBanned`, `IpUnbanned`, `RuleTriggered`, `ThresholdExceeded`, `ConfigChanged`. Host-App kann eigene Listener registrieren.
- **Facade `WAF`:** `WAF::ban($ip, $minutes, $reason)`, `WAF::unban($ip)`, `WAF::isBanned($ip)`, `WAF::score($ip, $points, $reason)`, `WAF::allow($ip)`, `WAF::mode()`.
- **Hooks im Code:** `WAF::skip()` innerhalb eines Controllers ist **nicht** vorgesehen (Prüfung läuft vorher); Umgehung ausschließlich über Ausnahmen/Profile.
- Standardmäßig ausgenommen: die WAF-UI selbst (nur Rate-Limit + Header, damit man sich nicht aussperrt), `/up` (Health), Challenge-Routen.

---

## 6. Clusterbetrieb

- **Quelle der Wahrheit:** MariaDB (Galera). Alle Tabellen haben einen **Primärschlüssel** (ULID als `CHAR(26)`), kein Verlass auf `AUTO_INCREMENT`-Reihenfolge, keine `LOCK TABLES`, keine `GET_LOCK`-Abhängigkeit.
- **Laufzeitzustand:** Redis (Bans, Reputation, Rate-Limits, Challenge-Nonces, kompilierte Regeln, Config). Schlüsselpräfix `waf:` + `config('waf.redis.prefix')` für mehrere Apps auf einer Redis-Instanz.
- **Konfigurationsverteilung:** Jede Änderung im UI erhöht `waf:config:version` und publiziert auf Kanal `waf:invalidate`. Jeder Knoten hält einen In-Process-Cache (APCu, sonst statisch pro Worker) und vergleicht pro Request nur die Version (ein `GET`); bei Abweichung wird neu geladen. Pub/Sub ist Optimierung, die Versionsprüfung die Garantie.
- **Logging im Hot-Path:** Ereignisse werden in eine Redis-Liste `waf:events:queue` geschrieben (`RPUSH`, nicht blockierend) und vom Scheduler-Job `waf:events:flush` (jede Minute, `withoutOverlapping()->onOneServer()`) gebündelt in die DB geschrieben (Batch-Insert à 500).
- **Scheduler-Jobs** laufen mit `onOneServer()`.
- **Client-IP:** Ausschließlich über Laravels `TrustProxies`. Dokumentierte Beispielkonfigurationen für Hetzner Load Balancer (PROXY-Protokoll bzw. `X-Forwarded-For` aus privaten Netzen) und ISPConfig/nginx-Reverse-Proxy.
- Octane-kompatibel: Engine-Services sind zustandslos pro Request; `RequestContext` wird pro Request neu erzeugt.

---

## 7. Datenschutz (DSGVO)

- **Keine Daten an Dritte.** Alles bleibt in der eigenen Infrastruktur.
- **IP-Anonymisierung** in gespeicherten Ereignissen nach `privacy.anonymize_after_days` (Standard 7): IPv4 → letztes Oktett `0`, IPv6 → /48. Bans/Allowlists sind ausgenommen (berechtigtes Interesse, eigene Ablaufdaten).
- **Pseudonymisierung:** Zusätzlich wird `ip_hash` (HMAC-SHA256 mit `WAF_PEPPER`) gespeichert, damit Statistiken nach Anonymisierung weiter gruppiert werden können.
- **Aufbewahrung:** Ereignisse Standard 30 Tage, Aggregatstatistiken 400 Tage; `waf:prune` täglich.
- **Redaktion:** Bevor Payload-Ausschnitte gespeichert werden, werden Felder mit sensiblen Namen geschwärzt (`password`, `passwort`, `token`, `secret`, `api_key`, `authorization`, `cookie`, `iban`, `credit_card`, `cvc`, `_token`; erweiterbar). Payloads werden auf 512 Zeichen um die Trefferstelle gekürzt. Bodies werden **nie** vollständig gespeichert.
- **Benutzerbezug:** `user_id` nur, wenn `privacy.store_user_id = true` (Standard `false`).
- Die Doku liefert einen Textbaustein für die Datenschutzerklärung (Abschnitt „Schutz vor Angriffen“, Art. 6 Abs. 1 lit. f DSGVO) unter `docs/datenschutz-baustein.md`.

---

## 8. Datenbank

Tabellenpräfix `waf_`. Alle IDs ULID. Zeitstempel UTC.

**`waf_rules`**
`id`, `code` (z. B. `WAF-SQLI-001`, unique), `source` (`core`, `custom`, `import`), `pack` (nullable), `pack_version`, `name`, `description`, `severity` (enum), `paranoia_level` (1–4), `priority`, `phase` (`request`, `response`), `conditions` (JSON), `transforms` (JSON), `action` (JSON), `mode_override` (nullable enum), `tags` (JSON), `is_active`, `created_by`, `updated_by`, Timestamps.

**`waf_exceptions`**
`id`, `rule_code` (nullable), `rule_tag` (nullable), `scope_type` (`global`, `route_name`, `path_pattern`), `scope_value`, `parameter` (nullable), `ip_cidr` (nullable), `comment`, `expires_at`, `created_by`, Timestamps. Index auf (`rule_code`, `scope_type`).

**`waf_ip_entries`**
`id`, `list` (`allow`, `deny`), `cidr` (VARCHAR 49), `ip_start` (VARBINARY 16), `ip_end` (VARBINARY 16), `source`, `comment`, `expires_at`, `created_by`, Timestamps. Index auf (`list`, `ip_start`, `ip_end`).

**`waf_bans`**
`id`, `ip_key` (IP bzw. /64-Präfix), `ip_hash`, `reason`, `rule_code` (nullable), `level` (Eskalationsstufe), `banned_until`, `lifted_at`, `lifted_by`, `source` (`auto`, `manual`, `api`, `honeypot`), Timestamps. Index auf (`ip_key`, `banned_until`).

**`waf_rate_limit_profiles`**
`id`, `name` (unique), `key_type`, `key_header` (nullable), `limit`, `window_seconds`, `burst`, `action` (JSON), `is_active`, Timestamps.

**`waf_profile_assignments`**
`id`, `profile_type` (`rate_limit`, `inspection`), `profile_id`, `match_type` (`route_name`, `path_pattern`, `method`), `match_value`, `priority`, Timestamps.

**`waf_inspection_profiles`**
`id`, `name`, `paranoia_level`, `inbound_threshold`, `mode_override`, `limits` (JSON, s. 5.12), `allowed_countries` (JSON), `denied_countries` (JSON), `denied_asns` (JSON), `upload_rules` (JSON), Timestamps.

**`waf_events`**
`id` (= Vorfall-ID), `occurred_at` (Index), `ip` (anonymisierbar), `ip_hash` (Index), `country`, `asn`, `method`, `host`, `path` (max. 2048), `route_name`, `user_agent` (max. 512), `user_id` (nullable), `mode`, `outcome` (`blocked`, `challenged`, `logged`, `banned`, `allowed`), `status_code`, `score`, `matches` (JSON: Liste aus `rule_code`, `target`, `parameter`, gekürzter geschwärzter Ausschnitt), `node` (Hostname des App-Servers), `anonymized_at`.
Indizes: (`occurred_at`), (`ip_hash`, `occurred_at`), (`outcome`, `occurred_at`).

**`waf_stats_hourly`**
`id`, `hour` (Datum+Stunde), `outcome`, `rule_code` (nullable), `country` (nullable), `count`. Unique auf (`hour`, `outcome`, `rule_code`, `country`). Befüllt durch `waf:events:flush` per `INSERT … ON DUPLICATE KEY UPDATE`.

**`waf_learning_hits`**
`id`, `rule_code`, `route_name`, `path_pattern`, `parameter`, `hit_count`, `distinct_ip_count`, `first_seen_at`, `last_seen_at`, `status` (`open`, `accepted`, `dismissed`). Unique auf (`rule_code`, `route_name`, `parameter`).

**`waf_csp_reports`**
`id`, `received_at`, `document_uri`, `violated_directive`, `blocked_uri`, `source_file`, `line`, `count` (dedupliziert pro Tag).

**`waf_settings`**
`key` (PK), `value` (JSON), `updated_by`, `updated_at`. Überschreibt Werte aus `config/waf.php` zur Laufzeit.

**`waf_audit_log`**
`id`, `user_id`, `action`, `subject_type`, `subject_id`, `changes` (JSON vorher/nachher), `ip`, `created_at`. Unveränderlich (kein Update/Delete über Models).

**`waf_notification_channels`**
`id`, `type` (`mail`, `webhook`), `target` (E-Mail oder URL), `secret` (verschlüsselt, für HMAC-Signatur), `events` (JSON), `min_severity`, `digest` (`instant`, `hourly`, `daily`), `is_active`, Timestamps.

Alle Models nutzen `HasUlids`. Verschlüsselte Spalten über `encrypted`-Cast.

---

## 9. Konfiguration (`config/waf.php`)

Wichtigste Schlüssel (alle über `.env` und – wo sinnvoll – über das UI änderbar):

```php
return [
    'enabled'           => env('WAF_ENABLED', true),
    'mode'              => env('WAF_MODE', 'detect'),          // off|learning|detect|block
    'fail_mode'         => env('WAF_FAIL_MODE', 'open'),       // open|closed
    'paranoia_level'    => (int) env('WAF_PARANOIA', 1),
    'inbound_threshold' => (int) env('WAF_THRESHOLD', 5),
    'pepper'            => env('WAF_PEPPER'),                  // Pflicht; waf:install erzeugt ihn
    'redis' => [
        'connection' => env('WAF_REDIS_CONNECTION', 'default'),
        'prefix'     => env('WAF_REDIS_PREFIX', 'waf:'),
    ],
    'ui' => [
        'enabled'    => env('WAF_UI_ENABLED', true),
        'path'       => env('WAF_UI_PATH', 'admin/waf'),
        'domain'     => env('WAF_UI_DOMAIN'),
        'middleware' => ['web', 'auth', 'verified'],
        'gate'       => 'viewWAF',
    ],
    'inspection' => [
        'max_body_bytes' => 65536,
        'json_max_depth' => 32,
        'excluded_paths' => ['up'],
    ],
    'reputation' => ['half_life_minutes' => 60, 'ban_threshold' => 50],
    'bans' => [
        'escalation'      => [15, 60, 1440, 10080],   // Minuten
        'reset_after_days'=> 30,
        'ipv6_prefix'     => 64,
    ],
    'challenge' => [
        'pow_difficulty' => 18,
        'pass_ttl_hours' => 12,
    ],
    'geoip' => [
        'country_db' => storage_path('app/waf/GeoLite2-Country.mmdb'),
        'asn_db'     => storage_path('app/waf/GeoLite2-ASN.mmdb'),
        'license_key'=> env('WAF_MAXMIND_LICENSE'),
        'auto_update'=> false,
    ],
    'clamav' => ['enabled' => false, 'socket' => 'unix:///var/run/clamav/clamd.ctl', 'timeout' => 5],
    'headers' => [ /* siehe 5.11, jeweils enabled + value */ ],
    'response_inspection' => ['enabled' => false, 'max_bytes' => 524288],
    'privacy' => [
        'anonymize_after_days' => 7,
        'retention_days'       => 30,
        'stats_retention_days' => 400,
        'store_user_id'        => false,
        'redact_keys'          => ['password','passwort','token','secret','api_key','authorization','cookie','iban','credit_card','cvc','_token'],
    ],
    'block_page' => ['contact' => env('WAF_CONTACT')],
];
```

Rangfolge: `waf_settings` (UI) > `.env`/Config > Paket-Standard. Sicherheitskritische Schlüssel (`pepper`, `redis`, `ui.middleware`, `ui.gate`, `fail_mode`) sind **nur** per Config änderbar, nicht per UI.

---

## 10. Verwaltungsoberfläche

### 10.1 Zugriff & Absicherung

- Routen unter `config('waf.ui.path')`, optional eigene Domain.
- Middleware aus Config + Gate `viewWAF`. Das Paket definiert das Gate **nicht** permissiv: Standard ist `false`, die Host-App muss es explizit definieren (z. B. in `AppServiceProvider`). `waf:install` gibt den Code-Schnipsel aus.
- Zusätzliche Fähigkeiten über Policies: `manageWAF` (Ändern), `viewWAFPayloads` (geschwärzte Payload-Ausschnitte sehen). Ohne `manageWAF` ist die UI schreibgeschützt.
- Alle schreibenden Aktionen: CSRF, FormRequest-Validierung, Audit-Log-Eintrag.
- Kritische Aktionen (Modus auf `off`, eigene IP von Allowlist entfernen, Regelpaket deaktivieren) erfordern Bestätigungsdialog mit Eingabe des Wortes „BESTÄTIGEN“.
- **Selbstaussperr-Schutz:** Vor dem Speichern von Deny-Einträgen, Geo-Regeln oder eigenen Regeln wird geprüft, ob die aktuelle Admin-IP betroffen wäre → Warnung mit Abbruchmöglichkeit.

### 10.2 Layout

Eigenes Layout `waf::layouts.app` (unabhängig vom Host-Layout), linke Seitennavigation, oben Statusleiste mit aktuellem Modus als farbigem Badge (off = grau, learning = blau, detect = gelb, block = grün) und Schnellumschalter. Responsive bis 360 px Breite.

### 10.3 Seiten

1. **Übersicht (Dashboard)**
   - Kennzahlen 24 h / 7 Tage / 30 Tage: Requests geprüft (Stichprobenzähler), blockiert, Challenges, gelöste Challenges, aktive Bans.
   - Diagramme (Chart.js): Zeitverlauf blockiert/geloggt, Top-10 Regeln, Top-10 Länder, Top-10 Pfade, Top-10 IPs (bzw. Hashes nach Anonymisierung).
   - Systemstatus: Redis erreichbar, Event-Warteschlangenlänge, letzter Flush, GeoIP-DB-Alter, ClamAV erreichbar, Regelversion pro Knoten (Knoten melden sich per Redis-Heartbeat `waf:nodes:<hostname>`, TTL 120 s), Konfigurationsversion synchron ja/nein.
   - Hinweise: z. B. „TrustProxies nicht konfiguriert“, „Modus seit 14 Tagen auf detect“, „GeoIP-Datenbank älter als 30 Tage“.

2. **Ereignisse**
   - Tabelle mit Filtern (Zeitraum, Ergebnis, Regel, IP, Land, Pfad, Statuscode), serverseitige Paginierung (50/Seite), Suche nach Vorfall-ID.
   - Detailansicht: alle Treffer mit Ziel, Parameter, Ausschnitt (nur mit `viewWAFPayloads`), Normalisierungsweg, Score-Aufschlüsselung.
   - Aktionen: „IP sperren“, „IP erlauben“, „Ausnahme anlegen“, „Als Fehlalarm markieren“ (legt Ausnahme-Vorschlag an).
   - Live-Ansicht: Polling alle 5 s per `fetch` auf JSON-Endpunkt (kein WebSocket nötig), pausierbar.
   - CSV-Export des gefilterten Ergebnisses.

3. **Regeln**
   - Reiter „Kernregeln“ (gruppiert nach Modul, aktiv/inaktiv, Paranoia-Level, Trefferzahl 7 Tage) und „Eigene Regeln“.
   - Regel-Editor als Formular mit Alpine-Komponente für Bedingungen (hinzufügen/entfernen, Vorschau der Regel als lesbarer Satz: „Wenn Pfad beginnt mit `/api/` UND Header `X-Key` fehlt, dann blockieren (403)“).
   - Regel-Tester (5.4).
   - Import/Export von Regelpaketen (JSON, Schema-Validierung beim Import, Vorschau der Änderungen vor Übernahme).

4. **Ausnahmen** — Liste, anlegen, bearbeiten, ablaufen lassen; Reiter „Vorschläge (Lernmodus)“.

5. **IP-Listen** — Reiter Allowlist, Denylist, Abonnierte Listen; Massenimport, Ablaufdaten, Suche „Ist IP X betroffen?“ (prüft Allow/Deny/Ban/Geo/ASN und zeigt die greifende Regel).

6. **Sperren** — Aktive Bans mit Restlaufzeit, Grund, Stufe; Aufheben (einzeln/Mehrfachauswahl); Verlauf.

7. **Rate-Limits** — Profile verwalten, Zuweisungen, aktuelle Spitzenreiter (Schlüssel nahe am Limit).

8. **Bot-Schutz** — Challenge-Typ und Schwierigkeit, Pass-Dauer, verifizierte Bots, Fallen-Routen, UA-Listen, Statistik Challenges gestellt/gelöst.

9. **Geo & ASN** — Länder-Auswahl (Mehrfachauswahl mit Suche, Flaggen-Emojis), ASN-Liste, GeoIP-Status und Aktualisierungsknopf.

10. **Uploads** — erlaubte Typen, Größen, ClamAV-Einstellungen und Verbindungstest.

11. **Security-Header** — Formular je Header mit Vorschau des resultierenden Headers; CSP-Baukasten (Direktiven als Liste); Reiter „CSP-Berichte“.

12. **Profile** — Inspektionsprofile (Paranoia, Schwellwert, Limits, Geo) und deren Zuweisungen.

13. **Benachrichtigungen** — Kanäle (E-Mail, Webhook mit HMAC-SHA256-Signatur im Header `X-WAF-Signature`), Ereignisarten, Mindestschwere, Sofort/Digest; Testversand.

14. **Einstellungen** — Modus, Paranoia, Schwellwerte, Reputation, Ban-Eskalation, Datenschutz-Einstellungen, Block-Seiten-Kontakt; Konfigurations-Export/-Import (JSON, ohne Geheimnisse).

15. **Audit-Log** — wer hat wann was geändert, mit Diff-Ansicht.

### 10.4 Frontend-Technik

- Keine Inline-Skripte und keine Inline-Event-Handler (CSP-tauglich, Alpine-CSP-Build mit `Alpine.data()`-Registrierung).
- Alle Skripte/Styles mit `nonce` aus `waf_nonce()`.
- JSON-Endpunkte unter `{ui.path}/api/*`, gleiche Auth-Middleware, Antworten als Laravel API Resources.
- Tabellen serverseitig gerendert (Blade), Alpine nur für Interaktion (Filter, Dialoge, Regel-Editor, Live-Polling, Diagramme).
- Toast-Meldungen für Erfolg/Fehler, Validierungsfehler am Feld.
- Leere Zustände mit erklärendem Text und Aktionsknopf.
- Barrierefreiheit: Labels an allen Feldern, Fokus-Reihenfolge, Kontrast gemäß WCAG AA, Diagramme zusätzlich als Tabelle.

---

## 11. Artisan-Befehle

| Befehl | Zweck |
|---|---|
| `waf:install` | Publizieren, migrieren, Pepper erzeugen, Kernregeln importieren, Gate-Schnipsel ausgeben, TrustProxies prüfen |
| `waf:status` | Modus, Regelversion, Redis/GeoIP/ClamAV-Status, aktive Bans, Knoten |
| `waf:mode {mode}` | Modus setzen (mit Audit-Eintrag „CLI“) |
| `waf:rules:import {file?}` | Regelpaket importieren (ohne Argument: mitgelieferte Kernregeln aktualisieren) |
| `waf:rules:export {file}` | Eigene Regeln exportieren |
| `waf:rules:test` | Interaktiver Test-Request oder `--payload=` / `--file=` |
| `waf:rules:compile` | Regeln neu kompilieren und verteilen |
| `waf:ban {ip} {--minutes=} {--reason=}` | IP sperren |
| `waf:unban {ip}` | Sperre aufheben |
| `waf:allow {ip} {--comment=} {--until=}` | Allowlist-Eintrag |
| `waf:sync` | Bans/IP-Listen aus DB nach Redis laden |
| `waf:events:flush` | Ereignis-Warteschlange in DB schreiben, Statistik aggregieren |
| `waf:prune` | Anonymisieren und Altdaten löschen |
| `waf:geoip:update` | GeoIP-Datenbanken aktualisieren |
| `waf:blocklists:update` | Abonnierte Blocklisten abrufen |
| `waf:notify:digest {period}` | Digest-Benachrichtigungen versenden |
| `waf:benchmark` | Misst Engine-Latenz mit Testkorpus (p50/p95/p99) |

**Scheduler** (vom ServiceProvider registriert, abschaltbar per `waf.schedule.enabled`):
`waf:events:flush` jede Minute, `waf:prune` täglich 03:15, `waf:notify:digest hourly` stündlich, `waf:notify:digest daily` täglich 07:00, `waf:blocklists:update` alle 6 h (falls aktiv), `waf:geoip:update` wöchentlich (falls `auto_update`). Alle mit `onOneServer()->withoutOverlapping()`.

---

## 12. Engine-Ablauf pro Request

1. Ausnahmepfade (UI, `/up`, Challenge-Routen) → nur Rate-Limit + Header.
2. Config-Version prüfen, ggf. Cache neu laden.
3. Client-IP bestimmen, IPv6 auf Präfix aggregieren.
4. **Allowlist** → durchlassen.
5. **Denylist / aktiver Ban** → 403.
6. **Geo/ASN** → gemäß Profil.
7. **Gültiges `waf_pass`-Cookie** merken (reduziert Bot-Prüfungen, nicht Angriffserkennung).
8. **Request-Grenzen** (5.12).
9. **Rate-Limits** der zutreffenden Profile.
10. **Bot-Prüfungen** und Fallen-Routen.
11. **Normalisierung** + **Regelauswertung** nach Priorität; `allow`-Aktion bricht ab; Ausnahmen werden vor Score-Addition angewandt.
12. **Upload-Prüfung**.
13. Score gegen Schwellwert → Aktion gemäß Modus.
14. Reputation aktualisieren, ggf. Auto-Ban.
15. Ereignis in Redis-Warteschlange (nur bei Treffer oder Aktion; saubere Requests werden lediglich gezählt: `INCR waf:counter:<stunde>`).
16. Nach dem Controller: Response-Inspektion, Security-Header, 404/Fehler-Zähler.

Jede Stufe ist eine eigene Klasse mit Interface `InspectionStage` (`handle(RequestContext $ctx): StageResult`). Reihenfolge per Config erweiterbar; Host-Apps können eigene Stages registrieren (`WAF::extend()`).

---

## 13. Benachrichtigungen

- Kanäle Mail (Laravel-Mailer der Host-App) und Webhook (POST JSON, Timeout 5 s, 3 Wiederholungen mit Backoff über Queue).
- Ereignisarten: Ban ausgelöst, Angriffswelle (> N Blocks/Minute), neue IP mit kritischem Treffer, Modusänderung, Konfigurationsänderung, Redis/ClamAV nicht erreichbar, GeoIP veraltet.
- Drosselung: gleiche Ereignisart max. 1× pro 10 min sofort, Rest in den nächsten Digest.
- Mails in Deutsch, im Designsystem, mit Link in die UI.

---

## 14. Tests & Qualität

- **Pest** mit **Orchestra Testbench**, Redis-Testinstanz (eigene DB-Nummer).
- **Angriffskorpus** `tests/Fixtures/attacks/*.txt` (je Modul ≥ 50 Payloads, inkl. Obfuskationen) → muss bei Paranoia 1 zu ≥ 95 % erkannt werden, bei Paranoia 2 zu ≥ 99 %.
- **Fehlalarm-Korpus** `tests/Fixtures/benign/*.txt` (deutsche Texte mit Apostrophen, Anführungszeichen, Code-Schnipsel in Markdown, Adressen, E-Mail-Adressen, JSON-Payloads typischer Formulare, URLs) → bei Paranoia 1 **0 Treffer**.
- Feature-Tests für jede UI-Route (Gate verweigert/erlaubt, Validierung, Audit-Eintrag).
- Tests für Cluster-Verhalten: Versionswechsel lädt Regeln neu, Bans überleben Redis-Flush via `waf:sync`.
- Tests für ReDoS-Ablehnung, Redaktion sensibler Felder, Anonymisierung.
- `waf:benchmark` in CI, Abbruch bei p95 > 2 ms.
- **Larastan** Level 8, **Pint** (Laravel-Preset), keine Warnungen.
- Kein Merge ohne grüne Tests.

---

## 15. Umsetzungsreihenfolge

1. Paketgerüst, ServiceProvider, Config, Install-Befehl, Testbench-Setup.
2. `RequestContext`, Normalizer, IP-Matcher (CIDR v4/v6), Redis-Zugriffsschicht mit Fail-Modus.
3. Migrationen + Models aller Tabellen.
4. Regel-DSL, Compiler, Matcher, Kernregelpaket `core-v1.json` mit allen Modulen aus 5.2, Angriffs- und Fehlalarm-Korpus.
5. Firewall-Middleware mit Stages 1–15, Scoring, Modi, Block-Seiten.
6. IP-Listen, Bans, Reputation, Auto-Ban, `waf:sync`.
7. Rate-Limiting inkl. Login-Bruteforce und 404-Flut.
8. Ereignis-Warteschlange, Flush, Statistik, Prune, Anonymisierung.
9. Bot-Schutz: UA-Regeln, Bot-Verifikation, Proof-of-Work-Challenge, Bild-Captcha, Honeypots.
10. Upload-Prüfung inkl. ClamAV.
11. Security-Header-Middleware, CSP-Nonce, CSP-Reports, Response-Inspektion.
12. Geo/ASN.
13. UI: Layout, Dashboard, Ereignisse, Regeln (Editor + Tester), Ausnahmen + Lernmodus, IP-Listen, Sperren, Rate-Limits, Bot-Schutz, Geo, Uploads, Header, Profile, Benachrichtigungen, Einstellungen, Audit-Log — je Seite in der 7-Schritt-Reihenfolge.
14. Benachrichtigungen, Digests.
15. Clusterverteilung (Versionierung, Pub/Sub, Knoten-Heartbeat).
16. Doku: `README.md` (Installation, Konfiguration, TrustProxies-Beispiele für Hetzner LB und ISPConfig/nginx, Gate-Definition, Erweiterung per eigener Stage), `docs/datenschutz-baustein.md`, `CHANGELOG.md`.

---

## Anhang A — Regelpaket-Schema (JSON)

```json
{
  "schema": "waf-rulepack/1",
  "pack": "core",
  "version": "1.0.0",
  "rules": [
    {
      "code": "WAF-SQLI-001",
      "name": "UNION-basierte SQL-Injection",
      "description": "Erkennt UNION SELECT in Parametern.",
      "severity": "critical",
      "paranoia_level": 1,
      "priority": 100,
      "phase": "request",
      "tags": ["sqli", "owasp-a03"],
      "transforms": ["urlDecodeUni", "removeComments", "compressWhitespace", "lowercase"],
      "conditions": {
        "match": "any",
        "items": [
          { "target": "query.*", "operator": "regex", "value": "\\bunion\\b\\s+(all\\s+)?\\bselect\\b" },
          { "target": "body.*",  "operator": "regex", "value": "\\bunion\\b\\s+(all\\s+)?\\bselect\\b" },
          { "target": "cookie.*","operator": "regex", "value": "\\bunion\\b\\s+(all\\s+)?\\bselect\\b" }
        ]
      },
      "action": { "type": "score" }
    }
  ]
}
```

- `conditions.match`: `all` | `any`; `items` dürfen eine weitere Gruppe `{ "match": …, "items": [...] }` enthalten (max. eine Ebene).
- `action.type`: `score` | `block` | `allow` | `challenge` | `log` | `ban` | `rate_limit` | `tag`, mit optionalen Feldern `status`, `minutes`, `profile`, `points`, `tag`.
- Validierung beim Import per JSON-Schema (`resources/rules/schema.json`); unbekannte Felder führen zum Abbruch mit verständlicher Fehlermeldung.
