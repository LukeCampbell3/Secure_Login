// client/vite.config.js
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import fs from 'fs'
import path from 'path'

const keyPath  = path.resolve(__dirname, '../certs/dev-key.pem')
const certPath = path.resolve(__dirname, '../certs/dev-cert.pem')

export default defineConfig({
  plugins: [react()],
  server: {
    https: fs.existsSync(keyPath) && fs.existsSync(certPath)
      ? { key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath) }
      : undefined,
    proxy: {
      '/api': {
        target: 'https://localhost:3000', // <- HTTPS (matches server)
        changeOrigin: true,
        secure: false, // accept self-signed in dev
      },
    },
  },
})