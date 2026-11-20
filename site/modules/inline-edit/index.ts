// Dev-only inline editor: Alt+click (Option+click on macOS) on a text in the running dev site, edit it, Enter saves the
// change back into the source file (site/app/**/*.vue|ts or the published docs/*.md), HMR shows it.
//
// Nothing of this exists outside `nuxt dev`: the module returns before registering anything when nuxt.options.dev is
// false (nuxt generate / nuxt build), the endpoint is a Vite dev-server middleware (configureServer never runs in a
// build) and the client plugin is only added in dev. Disable in dev with INLINE_EDIT=0.
import type { IncomingMessage, ServerResponse } from 'node:http'
import { readFileSync, readdirSync, realpathSync, statSync, writeFileSync } from 'node:fs'
import { join, relative, sep } from 'node:path'
import { addPlugin, addVitePlugin, createResolver, defineNuxtModule, useLogger } from '@nuxt/kit'
import { COLLECTIONS } from '../../app/utils/hub'
import { planEditScoped, type SourceFile } from './replace'

const ROUTE = '/__inline-edit'
const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]', '::1'])
const MAX_BODY = 64 * 1024

function walk(dir: string, exts: string[], out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    if (name.startsWith('.') || name === 'node_modules') continue
    const full = join(dir, name)
    const st = statSync(full)
    if (st.isDirectory()) walk(full, exts, out)
    else if (exts.some(e => name.endsWith(e))) out.push(full)
  }
  return out
}

const isLoopback = (addr = '') => addr === '::1' || addr.startsWith('127.') || addr.startsWith('::ffff:127.')

const hostnameOf = (hostHeader = '') => hostHeader.replace(/:\d+$/, '')

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let size = 0
    const chunks: Buffer[] = []
    req.on('data', (c: Buffer) => {
      size += c.length
      if (size > MAX_BODY) { reject(new Error('body too large')); req.destroy() }
      else chunks.push(c)
    })
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
    req.on('error', reject)
  })
}

function send(res: ServerResponse, status: number, body: unknown) {
  res.statusCode = status
  res.setHeader('content-type', 'application/json; charset=utf-8')
  res.setHeader('cache-control', 'no-store')
  res.end(JSON.stringify(body))
}

export default defineNuxtModule({
  meta: { name: 'inline-edit' },
  setup(_options, nuxt) {
    if (!nuxt.options.dev || process.env.INLINE_EDIT === '0') return
    const logger = useLogger('inline-edit')
    const { resolve } = createResolver(import.meta.url)

    const siteDir = realpathSync(nuxt.options.rootDir)
    const repoRoot = realpathSync(join(siteDir, '..'))
    const appDir = join(siteDir, 'app')
    // Only the folders the site renders. docs/internal/ is never searched or written.
    const docDirs = Object.values(COLLECTIONS).map(c => join(repoRoot, c.dir))
    const allowed = [appDir, ...docDirs].map(d => d + sep)
    // Docker (compose.yaml) reaches the server from the bridge gateway, not from loopback; the port itself is
    // published on 127.0.0.1 only. Opt in there with INLINE_EDIT_ALLOW_REMOTE=1.
    const allowRemote = process.env.INLINE_EDIT_ALLOW_REMOTE === '1'

    const sourceFiles = (): SourceFile[] => {
      const paths = [...walk(appDir, ['.vue', '.ts']), ...docDirs.flatMap(d => walk(d, ['.md']))]
      return paths
        .map(p => realpathSync(p))
        .filter(p => allowed.some(a => p.startsWith(a)) && !p.includes(`${sep}internal${sep}`))
        .map(p => ({ path: p, text: readFileSync(p, 'utf8') }))
    }

    async function handle(req: IncomingMessage, res: ServerResponse) {
      if (req.method !== 'POST') return send(res, 405, { error: 'POST only' })
      // CSRF / DNS rebinding: local Host and Origin only, JSON plus a custom header (forces a CORS preflight that we never answer).
      if (!allowRemote && !isLoopback(req.socket.remoteAddress)) return send(res, 403, { error: 'loopback only' })
      if (!LOCAL_HOSTS.has(hostnameOf(req.headers.host))) return send(res, 403, { error: 'bad host' })
      let origin: URL | null = null
      try { origin = new URL(String(req.headers.origin)) }
      catch {}
      if (!origin || !LOCAL_HOSTS.has(origin.hostname) || origin.host !== req.headers.host) return send(res, 403, { error: 'bad origin' })
      if (req.headers['x-inline-edit'] !== '1' || !String(req.headers['content-type']).startsWith('application/json')) {
        return send(res, 400, { error: 'bad request' })
      }

      let body: { oldText?: unknown, newText?: unknown, page?: unknown, files?: unknown }
      try { body = JSON.parse(await readBody(req)) }
      catch { return send(res, 400, { error: 'invalid body' }) }
      if (typeof body.oldText !== 'string' || typeof body.newText !== 'string') return send(res, 400, { error: 'oldText/newText missing' })

      // Component files from the client (Vue dev builds expose them); only paths inside the allowed folders count.
      const chain = (Array.isArray(body.files) ? body.files : [])
        .filter((f): f is string => typeof f === 'string')
        .flatMap((f) => { try { return [realpathSync(f)] } catch { return [] } })
        .filter(p => allowed.some(a => p.startsWith(a)))
      const plan = planEditScoped(sourceFiles(), chain, body.oldText, body.newText)
      if (!plan.ok) {
        return send(res, 409, { error: plan.error, matches: plan.matches?.map(m => ({ file: relative(repoRoot, m.path), line: m.line })) })
      }
      writeFileSync(plan.path, plan.text, 'utf8')
      const file = relative(repoRoot, plan.path)
      logger.info(`${file}:${plan.line} edited from ${String(body.page ?? '?')}`)
      return send(res, 200, { file, line: plan.line })
    }

    addVitePlugin({
      name: 'schild-inline-edit',
      apply: 'serve',
      configureServer(server) {
        server.middlewares.use(ROUTE, (req, res) => {
          handle(req, res).catch((e) => {
            logger.error(e)
            send(res, 500, { error: String(e?.message ?? e) })
          })
        })
      },
    }, { server: false })

    addPlugin({ src: resolve('./runtime/inline-edit.client'), mode: 'client' })
    logger.info(`Alt+click on a text to edit it (writes to site/app and ${COLLECTIONS.concept.dir.split('/')[0]}/). INLINE_EDIT=0 disables.`)
  },
})
