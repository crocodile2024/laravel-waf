# Textbaustein für die Datenschutzerklärung

> Dieser Baustein ist ein unverbindlicher Formulierungsvorschlag und ersetzt keine
> Rechtsberatung. Bitte an Ihre konkrete Konfiguration anpassen und rechtlich prüfen.

## Schutz vor Angriffen (Web Application Firewall)

Zum Schutz unserer Systeme vor Angriffen und missbräuchlicher Nutzung setzen wir eine
anwendungsseitige Web Application Firewall ein. Diese prüft eingehende Anfragen auf
bekannte Angriffsmuster (z. B. SQL-Injection, Cross-Site-Scripting) und wehrt
automatisierte Zugriffe ab.

Dabei verarbeiten wir folgende Daten, soweit eine Anfrage als sicherheitsrelevant
eingestuft wird:

- IP-Adresse,
- Zeitpunkt der Anfrage,
- aufgerufene Adresse (Pfad) und HTTP-Methode,
- technische Angaben des Browsers (User-Agent),
- sowie – geschwärzt und gekürzt – den Teil der Anfrage, der die Erkennung ausgelöst hat.

**Rechtsgrundlage** ist unser berechtigtes Interesse an der Sicherheit und
Verfügbarkeit unserer Dienste (Art. 6 Abs. 1 lit. f DSGVO).

**Speicherdauer:** IP-Adressen in den Sicherheitsereignissen werden nach spätestens
sieben Tagen anonymisiert (IPv4: letztes Oktett auf 0, IPv6: Kürzung auf /48).
Sicherheitsereignisse werden nach 30 Tagen gelöscht; anonyme Aggregatstatistiken
bewahren wir bis zu 400 Tage auf. Sperrlisten werden auf Basis eigener Ablaufzeiten
geführt.

**Keine Weitergabe an Dritte:** Die Verarbeitung findet ausschließlich in unserer
eigenen Infrastruktur statt. Es werden keine Daten an Dritte übermittelt, es kommt
kein externer Dienst (z. B. Captcha- oder Geo-Dienst eines Drittanbieters) zum Einsatz.

**Pseudonymisierung:** Zur statistischen Auswertung nach der Anonymisierung speichern
wir zusätzlich einen nicht umkehrbaren Hash der IP-Adresse (HMAC-SHA256 mit einem
geheimen Schlüssel). Ein Rückschluss auf die ursprüngliche IP-Adresse ist daraus nicht
möglich.

**Schwärzung sensibler Inhalte:** Felder mit sensiblen Bezeichnungen (etwa Passwörter,
Token, Zahlungsdaten) werden vor der Speicherung geschwärzt. Vollständige Anfrage-Inhalte
werden nicht gespeichert.
