import vue from '@vitejs/plugin-vue'
import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vitest/config'

export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: [
      { find: /^@schild\/ui$/, replacement: fileURLToPath(new URL('./src/index.ts', import.meta.url)) },
      { find: /^@schild\/ui\/(.*)$/, replacement: fileURLToPath(new URL('./src/$1', import.meta.url)) },
    ],
  },
  test: {
    globals: true,
    environment: 'jsdom',
    include: ['test/**/*.test.ts'],
    setupFiles: ['test/setup.ts'],
    css: false,
  },
})
