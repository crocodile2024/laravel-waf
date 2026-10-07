<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Http\Controllers;

use Crocodile2024\WAF\Models\AuditLog;
use Illuminate\Contracts\View\View;
use Illuminate\Http\Request;

class AuditController extends Controller
{
    public function index(Request $request): View
    {
        return view('waf::pages.audit', [
            'title' => 'Audit-Log',
            'entries' => AuditLog::query()
                ->when($request->filled('action'), fn ($q) => $q->where('action', $request->string('action')))
                ->when($request->filled('user'), fn ($q) => $q->where('user_id', 'like', '%'.$request->string('user').'%'))
                ->orderByDesc('created_at')->paginate(50)->withQueryString(),
            'filters' => $request->only(['action', 'user']),
        ]);
    }
}
