# Laravel WAF – Web Application Firewall

[![CI](https://github.com/crocodile2024/laravel-waf/actions/workflows/ci.yml/badge.svg)](https://github.com/crocodile2024/laravel-waf/actions/workflows/ci.yml)

Composer-Paket `crocodile2024/laravel-waf`, das jede Laravel-13-Anwendung mit einer
anwendungsseitigen **Web Application Firewall** inklusive Verwaltungsoberfläche ausstattet.

- **Self-hosted & DSGVO-konform** – keine externen Laufzeit-Aufrufe (kein CDN, kein
  reCAPTCHA, keine Cloud-GeoIP, keine Telemetrie). Einzige Ausnahme: der manuell
  ausgelöste Befehl `waf:geoip:update`.
- **Clustertauglich** – MariaDB/Galera als Quelle der Wahrheit, Redis für den
  Laufzeitzustand, Konfigurations- und Regelverteilung per Versionierung + Pub/Sub.
- **Schnell** – kompilierte Regeln aus Redis/APCu, keine DB-Abfrage im Hot-Path,
  Latenzbudget p95 ≤ 2 ms (in CI überwacht).

> Zielplattform: **Laravel 13, PHP 8.4, MariaDB, Redis**.

---

## Installation

```bash
composer require crocodile2024/laravel-waf
php artisan waf:install
```

### Assets

Das Paket liefert vorkompilierte Assets in `dist/` mit (Bootstrap 5.3, Alpine.js
im CSP-Build, Chart.js, Bootstrap Icons, alle Schriften lokal). `waf:install`
veröffentlicht sie nach `public/vendor/waf/`. Ein eigener Build ist nur bei
Paketentwicklung nötig:

```bash
npm ci
npm run build   # Vite → dist/ (gehashte Dateinamen + manifest.json)
```

`waf:install` publiziert Config, Assets und Migrationen, führt die Migration aus,
erzeugt den `WAF_PEPPER`, importiert die Kernregeln und gibt den Gate-Schnipsel aus.

### Gate definieren (Pflicht)

Das Paket definiert das UI-Gate **nicht permissiv** – ohne eine Definition in Ihrer
App ist die Oberfläche für niemanden zugänglich. In `app/Providers/AppServiceProvider.php`:

```php
use Illuminate\Support\Facades\Gate;

public function boot(): void
{
    // Lesender Zugriff auf die WAF-Oberfläche
    Gate::define('viewWAF', fn ($user) => $user->isAdmin());

    // Änderungen vornehmen (ohne diese Fähigkeit ist die UI schreibgeschützt)
    Gate::define('manageWAF', fn ($user) => $user->isAdmin());

    // Geschwärzte Payload-Ausschnitte einsehen
    Gate::define('viewWAFPayloads', fn ($user) => $user->isSecurityAdmin());
}
```

Die Oberfläche ist anschließend unter `/{waf.ui.path}` (Standard `admin/waf`) erreichbar.

---

## TrustProxies – unbedingt konfigurieren

Ohne korrekte Client-IP ist die WAF wirkungslos (alle Prüfungen sähen nur die IP des
Load Balancers). Konfigurieren Sie Laravels `TrustProxies` passend zu Ihrem Setup.

### Hetzner Load Balancer

Der Hetzner LB sendet `X-Forwarded-For`/`X-Forwarded-Proto` aus dem privaten Netz. In
`bootstrap/app.php`:

```php
->withMiddleware(function (Middleware $middleware) {
    $middleware->trustProxies(
        at: ['10.0.0.0/8', '172.16.0.0/12'], // privates Netz des LB
        headers: Request::HEADER_X_FORWARDED_FOR
            | Request::HEADER_X_FORWARDED_HOST
            | Request::HEADER_X_FORWARDED_PORT
            | Request::HEADER_X_FORWARDED_PROTO,
    );
})
```

Wird stattdessen das **PROXY-Protokoll** terminiert (z. B. nginx mit
`proxy_protocol`), setzen Sie die echte IP bereits im Reverse-Proxy
(`set_real_ip_from` / `real_ip_header proxy_protocol`) und vertrauen Sie dann dessen IP.

### ISPConfig / nginx als Reverse-Proxy

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host              $host;
    proxy_set_header X-Real-IP         $remote_addr;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

```php
->withMiddleware(function (Middleware $middleware) {
    $middleware->trustProxies(
        at: ['127.0.0.1', '::1'],
        headers: Request::HEADER_X_FORWARDED_FOR | Request::HEADER_X_FORWARDED_PROTO,
    );
})
```

`waf:install` warnt, wenn `TrustProxies` offenbar nicht konfiguriert ist.

---

## Betriebsmodi

| Modus      | Verhalten                                                              |
|------------|------------------------------------------------------------------------|
| `off`      | WAF deaktiviert (nur Security-Header bleiben, falls aktiv)             |
| `learning` | blockiert nichts; sammelt Treffer **und** Ausnahme-Vorschläge          |
| `detect`   | blockiert nichts; protokolliert und meldet Treffer                     |
| `block`    | Regelaktionen werden durchgesetzt                                      |

Empfehlung: zunächst `learning` oder `detect`, Fehlalarme über Ausnahmen bereinigen,
dann auf `block` umstellen.

```bash
php artisan waf:mode block
php artisan waf:status
```

---

## Konfiguration

Alle Schlüssel in `config/waf.php` sind dokumentiert und – wo sinnvoll – über die
Oberfläche änderbar. Rangfolge: **`waf_settings` (UI) > `.env`/Config > Paket-Standard**.

Sicherheitskritische Schlüssel (`pepper`, `redis`, `ui.middleware`, `ui.gate`,
`fail_mode`) sind **nur** per Config änderbar.

Wichtige `.env`-Werte:

```dotenv
WAF_ENABLED=true
WAF_MODE=detect
WAF_FAIL_MODE=open            # open = bei Redis-Ausfall durchlassen + loggen; closed = 503
WAF_PARANOIA=1
WAF_THRESHOLD=5
WAF_PEPPER=...                # von waf:install erzeugt – Pflicht
WAF_REDIS_CONNECTION=default
WAF_REDIS_PREFIX=waf:
WAF_UI_PATH=admin/waf
WAF_MAXMIND_LICENSE=          # optional, nur für waf:geoip:update
WAF_CONTACT=security@example.de
```

---

## Eigene Prüf-Stage registrieren

Die Engine ist erweiterbar. Host-Apps können eigene Logik als Facade-Hook einhängen:

```php
use Crocodile2024\WAF\Facades\WAF;

WAF::extend('my-stage', fn () => new \App\WAF\MyStage());
```

Programmatische Steuerung über die Facade:

```php
WAF::ban($ip, minutes: 60, reason: 'Missbrauch');
WAF::unban($ip);
WAF::isBanned($ip);
WAF::score($ip, points: 10);
WAF::allow($ip, comment: 'Büro-IP');
WAF::mode();           // aktueller Modus
```

Eine Umgehung der Prüfung aus dem Controller heraus ist **nicht** vorgesehen
(die Prüfung läuft vorher); nutzen Sie dafür Ausnahmen oder Profile.

---

## Artisan-Befehle

| Befehl | Zweck |
|---|---|
| `waf:install` | Publizieren, migrieren, Pepper, Kernregeln, Gate-Schnipsel |
| `waf:status` | Modus, Regelversion, Redis/GeoIP/ClamAV, aktive Bans, Knoten |
| `waf:mode {mode}` | Modus setzen |
| `waf:rules:import {file?}` | Regelpaket importieren / Kernregeln aktualisieren |
| `waf:rules:export {file}` | Eigene Regeln exportieren |
| `waf:rules:test` | Beispiel-Request testen (`--payload=` / `--file=`) |
| `waf:rules:compile` | Regeln neu kompilieren und verteilen |
| `waf:ban / waf:unban / waf:allow` | IP sperren / entsperren / erlauben |
| `waf:sync` | Bans/IP-Listen aus DB nach Redis laden |
| `waf:events:flush` | Ereigniswarteschlange in DB schreiben |
| `waf:prune` | Anonymisieren und Altdaten löschen |
| `waf:geoip:update` | GeoIP-Datenbanken aktualisieren |
| `waf:blocklists:update` | Abonnierte Blocklisten abrufen |
| `waf:notify:digest {period}` | Digest-Benachrichtigungen |
| `waf:benchmark` | Engine-Latenz messen (p50/p95/p99) |

Der ServiceProvider registriert die Scheduler-Jobs automatisch
(`onOneServer()->withoutOverlapping()`), abschaltbar über `waf.schedule.enabled`.

---

## Cluster-Betrieb

- **MariaDB (Galera)** ist die Quelle der Wahrheit; alle Tabellen haben einen ULID-PK,
  kein Verlass auf `AUTO_INCREMENT`, keine `LOCK TABLES`/`GET_LOCK`.
- **Redis** hält Laufzeitzustand (Bans, Reputation, Rate-Limits, Challenge-Nonces,
  kompilierte Regeln, Config). Schlüsselpräfix `waf:` + `config('waf.redis.prefix')`.
- **Verteilung:** Jede Änderung erhöht `waf:config:version` bzw. `waf:rules:version`
  und publiziert auf `waf:invalidate`. Jeder Knoten vergleicht pro Request nur die
  Version (ein `GET`); Pub/Sub ist die Optimierung, die Versionsprüfung die Garantie.
- Nach einem Redis-Neustart lädt `waf:sync` aktive Bans aus der DB zurück.

---

## Qualität

- **Pest** + **Orchestra Testbench**, Redis-Testinstanz.
- Angriffskorpus (Erkennung ≥ 95 % bei Paranoia 1, ≥ 99 % bei Paranoia 2) und
  Fehlalarm-Korpus (0 Treffer bei Paranoia 1).
- **Larastan Level 8**, **Pint** (Laravel-Preset).
- `waf:benchmark` bricht in CI bei p95 > 2 ms ab.

```bash
composer test       # Pest
composer analyse    # Larastan
composer format     # Pint
```

---

## Datenschutz

Siehe [`docs/datenschutz-baustein.md`](docs/datenschutz-baustein.md) für einen
Textbaustein zur Datenschutzerklärung. IP-Adressen werden nach
`privacy.anonymize_after_days` (Standard 7) anonymisiert, Ereignisse nach 30 Tagen
gelöscht; sensible Felder werden vor dem Speichern geschwärzt.

## Lizenz

MIT.
