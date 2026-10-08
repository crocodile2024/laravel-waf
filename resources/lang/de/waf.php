<?php

declare(strict_types=1);

return [
    'block' => [
        'title' => 'Zugriff blockiert',
        'heading' => 'Ihre Anfrage wurde blockiert',
        'intro' => 'Unsere Schutzmechanismen haben Ihre Anfrage als potenziell schädlich eingestuft und abgewiesen.',
        'incident' => 'Vorfall-ID',
        'time' => 'Zeitpunkt',
        'contact_hint' => 'Falls Sie glauben, dass es sich um einen Fehler handelt, nennen Sie bitte die Vorfall-ID.',
        'contact' => 'Kontakt',
    ],
    'challenge' => [
        'title' => 'Sicherheitsprüfung',
        'heading' => 'Kurze Sicherheitsprüfung',
        'intro' => 'Zum Schutz vor automatisierten Zugriffen führt Ihr Browser eine kleine Rechenaufgabe aus. Dies dauert nur einen Moment.',
        'working' => 'Prüfung läuft …',
        'nojs' => 'Bitte aktivieren Sie JavaScript, um fortzufahren.',
        'retry' => 'Die Lösung war nicht korrekt. Bitte versuchen Sie es erneut.',
        'captcha_fallback' => 'Kein JavaScript? Zur Bildprüfung wechseln.',
    ],
    'captcha' => [
        'intro' => 'Bitte geben Sie die Zeichen aus dem Bild ein, um fortzufahren.',
        'label' => 'Zeichen aus dem Bild',
        'submit' => 'Bestätigen',
        'alt' => 'Sicherheitscode als Bild',
        'contact_hint' => 'Sie können die Zeichen nicht erkennen? Bitte kontaktieren Sie uns:',
    ],
    'status' => [
        'off' => 'Aus', 'learning' => 'Lernen', 'detect' => 'Erkennen', 'block' => 'Blockieren',
    ],
];
