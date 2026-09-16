import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { defineConfig } from 'vite'

// Loom Studio frontend build config.
//
// - base: './' so the built assets work when served from any path by the
//   embedded Go binary (index.html references ./assets/... not /assets/...).
// - outDir: emits straight into internal/webui/dist, which is what
//   internal/webui embeds via go:embed at compile time.
// - dev server proxies /api/* to the running `loom -ui :9998` instance so
//   `npm run dev` works against a real backend with hot reload.
export default defineConfig({
  base: './',
  plugins: [react(), tailwindcss()],
  build: {
    outDir: '../internal/webui/dist',
    emptyOutDir: true,
  },
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:9998',
        changeOrigin: true,
      },
    },
  },
})
