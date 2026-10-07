<?php

declare(strict_types=1);

namespace Crocodile2024\WAF\Http\Controllers;

use Crocodile2024\WAF\Models\Event;
use Crocodile2024\WAF\Services\BanService;
use Crocodile2024\WAF\Services\IpListService;
use Illuminate\Contracts\View\View;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\Gate;
use Symfony\Component\HttpFoundation\StreamedResponse;

class EventController extends Controller
{
    public function index(Request $request): View
    {
        return view('waf::pages.events', [
            'title' => 'Ereignisse',
            'events' => $this->query($request)->paginate(50)->withQueryString(),
            'filters' => $request->only(['outcome', 'rule', 'ip', 'country', 'path', 'status', 'from', 'to', 'incident']),
            'canViewPayloads' => Gate::allows('viewWAFPayloads'),
        ]);
    }

    public function show(string $event): View
    {
        $model = Event::query()->findOrFail($event);

        return view('waf::pages.event-detail', [
            'title' => 'Ereignis '.$model->id,
            'event' => $model,
            'canViewPayloads' => Gate::allows('viewWAFPayloads'),
        ]);
    }

    public function stream(Request $request): JsonResponse
    {
        $events = $this->query($request)->limit(50)->get();

        return response()->json([
            'events' => $events->map(fn (Event $e) => [
                'id' => $e->id,
                'occurred_at' => $e->occurred_at?->toIso8601String(),
                'ip' => $e->ip,
                'country' => $e->country,
                'method' => $e->method,
                'path' => $e->path,
                'outcome' => $e->outcome,
                'status_code' => $e->status_code,
                'score' => $e->score,
            ]),
        ]);
    }

    public function export(Request $request): StreamedResponse
    {
        $query = $this->query($request);

        return response()->streamDownload(function () use ($query): void {
            $handle = fopen('php://output', 'wb');
            fputcsv($handle, ['Vorfall-ID', 'Zeitpunkt', 'IP', 'Land', 'Methode', 'Pfad', 'Ergebnis', 'Status', 'Score']);
            $query->chunk(500, function ($events) use ($handle): void {
                foreach ($events as $e) {
                    fputcsv($handle, [$e->id, $e->occurred_at, $e->ip, $e->country, $e->method, $e->path, $e->outcome, $e->status_code, $e->score]);
                }
            });
            fclose($handle);
        }, 'waf-ereignisse-'.now()->format('Ymd-His').'.csv', ['Content-Type' => 'text/csv']);
    }

    /**
     * @return \Illuminate\Database\Eloquent\Builder<Event>
     */
    private function query(Request $request)
    {
        return Event::query()
            ->when($request->filled('incident'), fn ($q) => $q->where('id', $request->string('incident')))
            ->when($request->filled('outcome'), fn ($q) => $q->where('outcome', $request->string('outcome')))
            ->when($request->filled('ip'), fn ($q) => $q->where('ip', 'like', $request->string('ip').'%'))
            ->when($request->filled('country'), fn ($q) => $q->where('country', $request->string('country')))
            ->when($request->filled('status'), fn ($q) => $q->where('status_code', (int) $request->integer('status')))
            ->when($request->filled('path'), fn ($q) => $q->where('path', 'like', '%'.$request->string('path').'%'))
            ->when($request->filled('rule'), fn ($q) => $q->where('matches', 'like', '%'.$request->string('rule').'%'))
            ->when($request->filled('from'), fn ($q) => $q->where('occurred_at', '>=', $request->date('from')))
            ->when($request->filled('to'), fn ($q) => $q->where('occurred_at', '<=', $request->date('to')))
            ->orderByDesc('occurred_at');
    }
}
