import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
  },
  test: {
    // Default: unit/component tests. With AEGIS_LIVE_API_URL set: only the real-backend tests.
    include: process.env.AEGIS_LIVE_API_URL
      ? ['src/__tests__/live.e2e.test.jsx']
      : ['src/**/*.test.jsx'],
    exclude: process.env.AEGIS_LIVE_API_URL ? [] : ['src/__tests__/live.e2e.test.jsx', 'node_modules/**'],
    environment: 'jsdom',
    globals: true,
    setupFiles: './src/__tests__/setupTests.js',
  },
});
