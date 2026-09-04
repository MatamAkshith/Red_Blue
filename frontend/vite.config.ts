import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    // Dev proxy to the FastAPI backend (uvicorn app.main:app).
    proxy: {
      '/incidents': 'http://127.0.0.1:8000',
      '/events': 'http://127.0.0.1:8000',
      '/investigate': 'http://127.0.0.1:8000',
    },
  },
})
