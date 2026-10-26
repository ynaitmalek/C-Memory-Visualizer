import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

// GitHub Pages project site: https://<user>.github.io/<repo>/ — CI sets VITE_BASE=/<repo>/.
// Locally it defaults to '/'. Assets (incl. any .wasm) are emitted relative to this base.
export default defineConfig({
  base: process.env.VITE_BASE ?? '/',
  plugins: [react(), tailwindcss()],
  worker: { format: 'es' },
});
