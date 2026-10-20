import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {strictPort: true, proxy: {'/api': 'http://127.0.0.1:18781'}},
  test: {environment: 'jsdom', setupFiles: './src/test-setup.ts', include: ['src/**/*.test.tsx']},
})
