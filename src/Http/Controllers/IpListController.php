<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Http\Controllers;

use Crocodile2024\WAF\Models\IpEntry;
use Crocodile2024\WAF\Services\AuditLogger;
use Crocodile2024\WAF\Services\BanService;
use Crocodile2024\WAF\Services\GeoIpService;
use Crocodile2024\WAF\Services\IpListService;
use Crocodile2024\WAF\Support\IpMatcher;
use Illuminate\Contracts\View\View;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;

class IpListController extends Controller
{
    public function __construct(
        private readonly IpListService $lists,
        private readonly BanService $bans,
        private readonly GeoIpService $geo,
        private readonly AuditLogger $audit,
    ) {}

    public function index(Request $request): View
    {
        $tab = in_array($request->query('tab'), ['allow', 'deny'], true) ? $request->query('tab') : 'allow';

        return view('waf::pages.ip-lists', [
            'title' => 'IP-Listen',
            'tab' => $tab,
            'entries' => IpEntry::query()->where('list', $tab)->orderByDesc('created_at')->paginate(50)->withQueryString(),
            'canManage' => Gate::allows('manageWAF'),
            'lookup' => $this->lookup($request),
        ]);
    }

    public function store(Request $request): RedirectResponse
    {
        $this->authorizeManage();
        $validated = $request->validate([
            'list' => ['required', 'in:allow,deny'],
            'cidr' => ['required', 'string', 'max:49'],
            'comment' => ['nullable', 'string', 'max:255'],
            'expires_at' => ['nullable', 'date'],
        ]);
        if (! IpMatcher::isValidCidr($validated['cidr'])) {
            return back()->withErrors(['cidr' => 'Ungültige IP/CIDR.'])->withInput();
        }
        // Selbstaussperr-Schutz
        if ($validated['list'] === 'deny' && IpMatcher::contains($validated['cidr'], (string) $request->ip())) {
            if (! $request->boolean('confirm_self')) {
                return back()->withErrors(['cidr' => 'Warnung: Ihre eigene IP wäre betroffen. Zum Fortfahren „Trotzdem sperren" bestätigen.'])->withInput();
            }
        }
        $entry = $this->lists->add($validated['list'], $validated['cidr'], [
            'comment' => $validated['comment'] ?? null,
            'expires_at' => $validated['expires_at'] ?? null,
            'source' => 'manual',
        ]);
        $this->audit->log('iplist.add', 'ip_entry', $entry->id, ['list' => $validated['list'], 'cidr' => $entry->cidr]);

        return back()->with('status', 'Eintrag hinzugefügt: '.$entry->cidr);
    }

    public function destroy(IpEntry $ipEntry): RedirectResponse
    {
        $this->authorizeManage();
        $this->audit->log('iplist.remove', 'ip_entry', $ipEntry->id, ['list' => $ipEntry->list, 'cidr' => $ipEntry->cidr]);
        $this->lists->remove($ipEntry->id);

        return back()->with('status', 'Eintrag entfernt.');
    }

    public function import(Request $request): RedirectResponse
    {
        $this->authorizeManage();
        $validated = $request->validate([
            'list' => ['required', 'in:allow,deny'],
            'entries' => ['required', 'string', 'max:1048576'],
        ]);
        $count = 0;
        foreach (preg_split('/\r?\n/', $validated['entries']) ?: [] as $line) {
            $line = trim((string) preg_replace('/[#;].*$/', '', $line));
            if ($line !== '' && IpMatcher::isValidCidr($line)) {
                try {
                    $this->lists->add($validated['list'], $line, ['source' => 'import']);
                    $count++;
                } catch (\Throwable) {
                }
            }
        }
        $this->audit->log('iplist.import', 'ip_entry', null, ['list' => $validated['list'], 'count' => $count]);

        return back()->with('status', "{$count} Einträge importiert.");
    }

    /**
     * „Ist IP X betroffen?" – prüft Allow/Deny/Ban/Geo/ASN.
     *
     * @return array<string, mixed>|null
     */
    private function lookup(Request $request): ?array
    {
        $ip = (string) $request->query('lookup', '');
        if ($ip === '' || ! IpMatcher::isValidIp($ip)) {
            return null;
        }

        return [
            'ip' => $ip,
            'allow' => $this->lists->matchingEntry('allow', $ip),
            'deny' => $this->lists->matchingEntry('deny', $ip),
            'banned' => $this->bans->isBanned($ip),
            'country' => $this->geo->available() ? $this->geo->country($ip) : null,
            'asn' => $this->geo->available() ? $this->geo->asn($ip) : null,
        ];
    }

    private function authorizeManage(): void
    {
        abort_unless(Gate::allows('manageWAF'), 403);
    }
}
