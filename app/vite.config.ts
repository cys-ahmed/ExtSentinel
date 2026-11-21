import path from "path"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"
import { inspectAttr } from 'kimi-plugin-inspect-react'
import { resolve } from 'path'
import fs from 'fs'

// https://vite.dev/config/
export default defineConfig({
  base: './',
  plugins: [
    inspectAttr(),
    react(),
    {
      name: 'copy-manifest',
      closeBundle() {
        const manifestSrc = resolve(__dirname, 'manifest.json')
        const manifestDest = resolve(__dirname, 'dist/manifest.json')
        if (fs.existsSync(manifestSrc)) {
          fs.copyFileSync(manifestSrc, manifestDest)
        }
      }
    }
  ],
  server: {
    port: 3000,
  },
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  build: {
    rollupOptions: {
      input: {
        popup: resolve(__dirname, 'popup.html'),
        options: resolve(__dirname, 'options.html'),
        welcome: resolve(__dirname, 'welcome.html'),
        background: resolve(__dirname, 'src/background/index.ts'),
        content: resolve(__dirname, 'src/content/index.ts'),
      },
      output: {
        entryFileNames: (chunk) => {
          if (chunk.name === 'background') return 'background.js'
          if (chunk.name === 'content') return 'content.js'
          return 'assets/[name]-[hash].js'
        },
        chunkFileNames: 'assets/[name]-[hash].js',
        assetFileNames: (assetInfo) => {
          const info = assetInfo.name || ''
          if (info.endsWith('.css')) {
            if (info.includes('popup')) return 'popup.css'
            if (info.includes('options')) return 'options.css'
            return 'assets/[name]-[hash][extname]'
          }
          return 'assets/[name]-[hash][extname]'
        },
      },
    },
  },
});
