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
        'retry' => 'Erneut versuchen',
    ],
    'status' => [
        'off' => 'Aus', 'learning' => 'Lernen', 'detect' => 'Erkennen', 'block' => 'Blockieren',
    ],
];
