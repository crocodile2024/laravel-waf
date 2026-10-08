# Changelog

Alle nennenswerten Änderungen an diesem Paket werden hier dokumentiert.
Das Format orientiert sich an [Keep a Changelog](https://keepachangelog.com/de/1.1.0/),
die Versionierung an [Semantic Versioning](https://semver.org/lang/de/).

## [Unveröffentlicht]

### Hinzugefügt
- Login-Bruteforce-Schutz: Listener auf `Auth\Events\Failed`/`Lockout`, Zählung je
  IP und je gehashter Benutzerkennung, Challenge ab Schwelle, danach Ban.
- Formular-Honeypot: Blade-Komponente `<x-waf::honeypot />` (verstecktes Feld +
  signierter Zeitstempel), Erkennung als `WAF-BOT-010`.
- Ausführung zusätzlicher, per `WAF::extend()` registrierter Inspection-Stages in der
  Engine (StageRegistry, `StageResult`: continue/stop/act).- Erste Implementierung der Web Application Firewall für Laravel 13 / PHP 8.4.
- Request-Normalisierung, SQLi-/XSS-Detektoren, Regel-DSL mit Compiler (ReDoS-Schutz)
  und Matcher.
- Kernregelpaket `core-v1.json` (SQLI, XSS, LFI, RFI, RCE, PHP, SSRF, XXE, NOSQL,
  PROTO, JNDI, PPOL, SCAN, BOT, LEAK).
- Firewall-Engine mit Stufen 1–15, Anomalie-Scoring, Paranoia-Level und Betriebsmodi
  (off/learning/detect/block).
- IP-Listen (Allow/Deny), Bans mit Eskalation, IP-Reputation mit Zerfall, Auto-Ban.
- Rate-Limiting (GCRA), Login-Bruteforce-/404-Flut-Schutz.
- Bot-Schutz: Suchmaschinen-Verifikation, Proof-of-Work-Challenge, `waf_pass`-Cookie,
  Fallen-Routen, Formular-Honeypot.
- Upload-Prüfung inkl. optionalem ClamAV; Security-Header-Middleware mit CSP-Nonce,
  CSP-Report-Endpunkt; optionale Response-Inspektion.
- Geo-/ASN-Filter über lokale MMDB-Dateien.
- Ereignis-Warteschlange mit gebündeltem DB-Flush, Statistikaggregation, Anonymisierung
  und Datenlöschung (DSGVO).
- Verwaltungsoberfläche: alle 15 Seiten – Dashboard, Ereignisse, Regeln (Editor + Tester),
  Ausnahmen (inkl. Lernmodus-Vorschläge), IP-Listen, Sperren, Rate-Limits, Bot-Schutz,
  Geo & ASN, Uploads, Security-Header (inkl. CSP-Berichte), Profile, Benachrichtigungen,
  Einstellungen und Audit-Log.
- 18 Artisan-Befehle inkl. `waf:install` und `waf:benchmark`.
- Clusterverteilung über Versionierung und Redis-Pub/Sub.
- Benachrichtigungen (Mail, Webhook mit HMAC-Signatur) mit Drosselung und Digest.
- Test-Suite (Pest + Testbench), Angriffs-/Fehlalarm-Korpus, Latenzbudget-Prüfung,
  Larastan Level 8, Pint.
