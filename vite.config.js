import { defineConfig } from 'vite';

// Baut die lokalen WAF-UI-Assets nach dist/ mit Hash im Dateinamen und Manifest.
// Keine CDN-Abhängigkeiten – Bootstrap, Alpine (CSP), Chart.js und Schriften
// werden gebündelt ausgeliefert.
export default defineConfig({
    build: {
        outDir: 'dist',
        emptyOutDir: true,
        manifest: 'manifest.json',
        rollupOptions: {
            input: { waf: 'resources/js/waf.js' },
        },
    },
});
