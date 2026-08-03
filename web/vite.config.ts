import path from 'node:path'

import tailwindcss from '@tailwindcss/vite'
import { tanstackRouter } from '@tanstack/router-plugin/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

export default defineConfig({
  // Relative asset URLs. The built app is embedded into the Go binary and may
  // be served from a path we do not control, so nothing can be absolute.
  base: './',

  plugins: [
    // Must precede react(): the router plugin generates route modules that the
    // React plugin then transforms.
    tanstackRouter({ target: 'react', autoCodeSplitting: true }),
    react(),
    tailwindcss(),
  ],

  resolve: {
    alias: { '@': path.resolve(import.meta.dirname, './src') },
  },

  server: {
    port: 5173,
    // `pindrop serve` owns the API during frontend development.
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:7777',
        changeOrigin: true,
      },
    },
  },

  build: {
    outDir: 'dist',
    emptyOutDir: true,
    // The Go binary embeds whatever is here, so a stale sourcemap would ship
    // to users. Keep them out of the release artifact.
    sourcemap: false,
  },
})
