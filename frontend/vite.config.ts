import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  envDir: '..',
  plugins: [react()],
  server: { host: '127.0.0.1', port: 5173 },
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          const dependency = id.split('node_modules/')[1] || ''
          if (dependency.startsWith('recharts/') || dependency.startsWith('victory-vendor/')) return 'charts'
          if (dependency.startsWith('framer-motion/') || dependency.startsWith('motion/')) return 'motion'
          if (dependency.startsWith('react/') || dependency.startsWith('react-dom/') || dependency.startsWith('react-router')) return 'framework'
        },
      },
    },
  },
})
