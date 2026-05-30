import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      '/api0': { target: 'http://localhost:5000', rewrite: p => p.replace(/^\/api0/, '') },
      '/api1': { target: 'http://localhost:5001', rewrite: p => p.replace(/^\/api1/, '') },
      '/api2': { target: 'http://localhost:5002', rewrite: p => p.replace(/^\/api2/, '') },
    }
  }
})
