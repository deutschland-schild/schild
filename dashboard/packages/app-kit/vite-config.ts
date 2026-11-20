import type { Plugin, UserConfig } from 'vite'
import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import tailwindcss from '@tailwindcss/vite'
import vue from '@vitejs/plugin-vue'

const here = dirname(fileURLToPath(import.meta.url))
/** dashboard */
export const uiRoot = resolve(here, '../..')
/** contracts */
export const contractsRoot = resolve(uiRoot, '../contracts')

/**
 * The colour scheme script that runs before first paint (packages/ui/src/theme-init.js), one file for both
 * apps and modes: served by the dev server, written next to index.html by the build. A classic script
 * from 'self', not inline, for the strict CSP.
 */
function themeInit(): Plugin {
  const file = resolve(uiRoot, 'packages/ui/src/theme-init.js')
  return {
    name: 'schild-theme-init',
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        if (req.url?.split('?')[0] !== '/theme-init.js') return next()
        res.setHeader('Content-Type', 'text/javascript')
        res.end(readFileSync(file, 'utf8'))
      })
    },
    transformIndexHtml: () => [{ tag: 'script', attrs: { src: './theme-init.js' }, injectTo: 'head' }],
    generateBundle() {
      this.emitFile({ type: 'asset', fileName: 'theme-init.js', source: readFileSync(file, 'utf8') })
    },
  }
}

/**
 * Shared Vite config for the dashboards.
 * - base './': assets resolve relative to index.html, so dist/ can be served by go:embed at root or under any sub-path.
 * - mode 'mock': serves MSW's worker from public-mock/ and enables fixtures from contracts/api/fixtures.
 */
export function dashboardConfig(appDir: string, mode: string, port: number): UserConfig {
  const mock = mode === 'mock'
  return {
    base: './',
    plugins: [vue(), tailwindcss(), themeInit()],
    publicDir: mock ? resolve(appDir, 'public-mock') : resolve(appDir, 'public'),
    resolve: {
      alias: [
        { find: /^@schild\/ui\/styles\.css$/, replacement: resolve(uiRoot, 'packages/ui/src/styles/index.css') },
        { find: /^@schild\/ui$/, replacement: resolve(uiRoot, 'packages/ui/src/index.ts') },
        { find: /^@schild\/ui\/(.*)$/, replacement: resolve(uiRoot, 'packages/ui/src/$1') },
        { find: /^@schild\/app-kit$/, replacement: resolve(uiRoot, 'packages/app-kit/src/index.ts') },
        { find: /^@\//, replacement: `${resolve(appDir, 'src')}/` },
      ],
    },
    server: {
      port,
      strictPort: false,
      fs: { allow: [uiRoot, contractsRoot] },
    },
    preview: { port },
    build: {
      outDir: 'dist',
      emptyOutDir: true,
      sourcemap: false,
      chunkSizeWarningLimit: 900,
      // Hashed file names, everything under assets/ next to index.html.
      assetsDir: 'assets',
      // Never inline assets as data: URIs: the dashboards' CSP allows fonts and
      // scripts only from 'self' (small font subsets would otherwise be inlined).
      assetsInlineLimit: 0,
    },
  }
}
