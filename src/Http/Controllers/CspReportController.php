<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Http\Controllers;

use Crocodile2024\WAF\Models\CspReport;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\DB;
use Throwable;

class CspReportController extends Controller
{
    public function store(Request $request): Response
    {
        try {
            $data = json_decode((string) $request->getContent(), true);
            $report = $data['csp-report'] ?? ($data['body'] ?? $data);
            if (! is_array($report)) {
                return response()->noContent();
            }
            $doc = mb_substr((string) ($report['document-uri'] ?? $report['documentURL'] ?? ''), 0, 1024);
            $directive = mb_substr((string) ($report['violated-directive'] ?? $report['effectiveDirective'] ?? ''), 0, 255);
            $blocked = mb_substr((string) ($report['blocked-uri'] ?? $report['blockedURL'] ?? ''), 0, 1024);
            $source = mb_substr((string) ($report['source-file'] ?? ''), 0, 1024);
            $line = (int) ($report['line-number'] ?? $report['lineNumber'] ?? 0);
            $fingerprint = hash('sha256', $directive.'|'.$blocked.'|'.$source.'|'.$line);

            DB::transaction(function () use ($doc, $directive, $blocked, $source, $line, $fingerprint): void {
                $row = CspReport::query()->lockForUpdate()->firstOrNew([
                    'received_at' => now()->toDateString(),
                    'fingerprint' => $fingerprint,
                ]);
                $row->document_uri = $doc;
                $row->violated_directive = $directive;
                $row->blocked_uri = $blocked;
                $row->source_file = $source;
                $row->line = $line ?: null;
                $row->count = ($row->count ?? 0) + 1;
                $row->save();
            });
        } catch (Throwable) {
            // CSP-Reports dürfen nie einen Fehler verursachen.
        }

        return response()->noContent();
    }
}
