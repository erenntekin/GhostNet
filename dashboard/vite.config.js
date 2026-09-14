import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  optimizeDeps: {
    include: ['react-globe.gl', 'prop-types'],
  },
  // host: true binds 0.0.0.0 instead of localhost -- required for the dev
  // server to be reachable from outside its Docker container. Harmless for
  // bare `npm run dev` on the host too.
  //
  // usePolling: native filesystem events (inotify) don't reliably cross
  // Docker Desktop's bind mount from this repo's Windows/OneDrive-synced
  // host path into the Linux container -- same underlying class of problem
  // already seen with uvicorn --reload on this project. Polling trades a
  // small amount of CPU for file changes actually being noticed.
  server: {
    host: true,
    port: 5173,
    watch: {
      usePolling: true,
      interval: 300,
    },
  },
})
