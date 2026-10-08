<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ $label }}</title>
</head>
<body style="margin:0;padding:0;background:#f5f4f0;font-family:'Plus Jakarta Sans',-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#1f2430;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f5f4f0;padding:24px 0;">
        <tr><td align="center">
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;background:#ffffff;border-radius:16px;overflow:hidden;border:1px solid rgba(31,36,48,.08);">
                <tr><td style="background:#4f46e5;padding:20px 28px;">
                    <span style="color:#ffffff;font-size:1.3rem;font-family:Georgia,'Times New Roman',serif;">WAF</span>
                    <span style="color:rgba(255,255,255,.85);font-size:.95rem;float:right;padding-top:6px;">Web Application Firewall</span>
                </td></tr>
                <tr><td style="padding:28px;">
                    <h1 style="margin:0 0 6px;font-size:1.5rem;font-weight:400;font-family:Georgia,'Times New Roman',serif;">
                        @if($period){{ 'Zusammenfassung (' . ($period === 'daily' ? 'täglich' : 'stündlich') . ')' }}@else{{ $label }}@endif
                    </h1>
                    <p style="margin:0 0 20px;color:#6b7280;line-height:1.6;">
                        @if($period)Im Berichtszeitraum sind folgende Ereignisse aufgelaufen.@else{{ $description }}@endif
                    </p>

                    @if($period)
                        <ul style="margin:0 0 20px;padding-left:18px;color:#1f2430;line-height:1.7;">
                            @foreach($items as $item)
                                <li style="font-size:.92rem;">{{ \Illuminate\Support\Str::limit((string) $item, 200) }}</li>
                            @endforeach
                        </ul>
                    @elseif(!empty($payload))
                        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f5f4f0;border-radius:10px;margin:0 0 20px;">
                            @foreach($payload as $key => $value)
                                <tr>
                                    <td style="padding:8px 14px;color:#6b7280;font-size:.85rem;width:38%;vertical-align:top;">{{ $key }}</td>
                                    <td style="padding:8px 14px;font-family:'JetBrains Mono',monospace;font-size:.85rem;word-break:break-all;">{{ is_scalar($value) ? (string) $value : json_encode($value, JSON_UNESCAPED_UNICODE) }}</td>
                                </tr>
                            @endforeach
                        </table>
                    @endif

                    <p style="margin:0 0 24px;color:#6b7280;font-size:.85rem;">Zeitpunkt: {{ $occurredAt }}</p>

                    @if($uiUrl)
                        <a href="{{ $uiUrl }}" style="display:inline-block;background:#4f46e5;color:#ffffff;text-decoration:none;padding:11px 22px;border-radius:9px;font-size:.95rem;">Zur Verwaltungsoberfläche</a>
                    @endif
                </td></tr>
                <tr><td style="padding:16px 28px;background:#f5f4f0;color:#9ca3af;font-size:.78rem;line-height:1.5;">
                    Diese Nachricht wurde automatisch von Ihrer Web Application Firewall erzeugt. Es werden keine Daten an Dritte übermittelt.
                </td></tr>
            </table>
        </td></tr>
    </table>
</body>
</html>
