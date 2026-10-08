/**
 * WAF-Verwaltungsoberfläche – Alpine.js (CSP-Build) + Chart.js, lokal gebündelt.
 *
 * CSP-tauglich: keine Inline-Skripte, keine Inline-Event-Handler. Interaktion
 * ausschließlich über registrierte Alpine.data()-Komponenten.
 */

import '../sass/waf.scss';
import '@fontsource/instrument-serif/400.css';
import '@fontsource/plus-jakarta-sans/400.css';
import '@fontsource/plus-jakarta-sans/600.css';
import '@fontsource/plus-jakarta-sans/700.css';
import '@fontsource/jetbrains-mono/400.css';
import 'bootstrap-icons/font/bootstrap-icons.css';
import Alpine from '@alpinejs/csp';
import {
    Chart,
    LineController, BarController,
    LineElement, BarElement, PointElement,
    CategoryScale, LinearScale,
    Tooltip, Legend,
} from 'chart.js';

Chart.register(
    LineController, BarController,
    LineElement, BarElement, PointElement,
    CategoryScale, LinearScale,
    Tooltip, Legend,
);

const INDIGO = '#4f46e5';
const AMBER = '#f59e0b';

/**
 * Dashboard: lädt Kennzahlen/Diagrammdaten vom JSON-Endpunkt und rendert Chart.js.
 * Barrierefreiheit: die Diagramme sind im Markup zusätzlich als Tabelle vorhanden.
 */
Alpine.data('wafDashboard', () => ({
    loading: true,
    charts: {},
    init() {
        this.load();
    },
    async load() {
        try {
            const res = await fetch(this.$root.dataset.endpoint, { headers: { Accept: 'application/json' } });
            if (!res.ok) return;
            const data = await res.json();
            this.renderTimeline(data.charts?.timeline || {});
            this.renderBars('waf-chart-rules', data.charts?.top_rules || {}, 'Treffer');
            this.renderBars('waf-chart-countries', data.charts?.top_countries || {}, 'Treffer');
        } catch (e) {
            // Diagramme sind optional; die Tabellen bleiben sichtbar.
        } finally {
            this.loading = false;
        }
    },
    renderTimeline(timeline) {
        const canvas = document.getElementById('waf-chart-timeline');
        if (!canvas) return;
        const labels = Object.keys(timeline);
        const blocked = labels.map((h) => sumOutcome(timeline[h], 'blocked'));
        const logged = labels.map((h) => sumOutcome(timeline[h], 'logged'));
        this.draw(canvas, 'line', {
            labels,
            datasets: [
                { label: 'Blockiert', data: blocked, borderColor: INDIGO, backgroundColor: INDIGO, tension: 0.3 },
                { label: 'Protokolliert', data: logged, borderColor: AMBER, backgroundColor: AMBER, tension: 0.3 },
            ],
        });
    },
    renderBars(id, map, label) {
        const canvas = document.getElementById(id);
        if (!canvas) return;
        this.draw(canvas, 'bar', {
            labels: Object.keys(map),
            datasets: [{ label, data: Object.values(map), backgroundColor: INDIGO }],
        });
    },
    draw(canvas, type, data) {
        if (this.charts[canvas.id]) this.charts[canvas.id].destroy();
        this.charts[canvas.id] = new Chart(canvas, {
            type,
            data,
            options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: type === 'line' } } },
        });
    },
}));

function sumOutcome(rows, outcome) {
    if (!Array.isArray(rows)) return 0;
    return rows.filter((r) => r.outcome === outcome).reduce((a, r) => a + Number(r.total || 0), 0);
}

/**
 * Live-Ansicht der Ereignisse: Polling alle 5 s auf den JSON-Endpunkt, pausierbar.
 */
Alpine.data('wafLiveEvents', () => ({
    paused: false,
    rows: [],
    timer: null,
    init() {
        this.tick();
        this.timer = setInterval(() => { if (!this.paused) this.tick(); }, 5000);
    },
    destroy() {
        if (this.timer) clearInterval(this.timer);
    },
    togglePause() {
        this.paused = !this.paused;
    },
    async tick() {
        try {
            const res = await fetch(this.$root.dataset.endpoint, { headers: { Accept: 'application/json' } });
            if (res.ok) {
                const data = await res.json();
                this.rows = data.events || [];
            }
        } catch (e) { /* stillschweigend */ }
    },
}));

/**
 * Bestätigungsdialog für kritische Aktionen (Eingabe des Wortes BESTÄTIGEN).
 */
Alpine.data('wafConfirm', () => ({
    word: '',
    get ok() {
        return this.word.trim() === 'BESTÄTIGEN';
    },
}));

window.Alpine = Alpine;
Alpine.start();
