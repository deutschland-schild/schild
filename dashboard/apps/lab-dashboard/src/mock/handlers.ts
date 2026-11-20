import type { HttpHandler } from 'msw'
import type { LabMock, MockResult } from './state'
import { delay, http, HttpResponse, sse } from 'msw'

function respond(r: MockResult) {
  if (r.status === 204 || r.body === undefined) return new HttpResponse(null, { status: r.status })
  const isProblem = r.status >= 400
  return HttpResponse.json(r.body as never, { status: r.status, headers: isProblem ? { 'Content-Type': 'application/problem+json' } : undefined })
}

async function json<T>(req: Request): Promise<T> {
  try {
    return (await req.json()) as T
  }
  catch {
    return {} as T
  }
}

/**
 * MSW handlers for the lab API in mock mode, backed by the stateful LabMock.
 * `prefix` is the server path from the spec ("/api/v0"); the app may be served under any sub-path.
 */
export function labHandlers(mock: LabMock, prefix: string, latency = 150): HttpHandler[] {
  const p = (path: string) => `*${prefix}${path}`
  type Ctx = { request: Request, params: Record<string, string | readonly string[] | undefined> }
  const guarded = (fn: (c: Ctx & { q: URLSearchParams }) => MockResult | Promise<MockResult>) => async ({ request, params }: Ctx) => {
    await delay(latency)
    const denied = mock.guard(request.method, request.headers.get('X-CSRF-Token'))
    if (denied) return respond(denied)
    return respond(await fn({ request, params, q: new URL(request.url).searchParams }))
  }
  const open = (fn: (c: Ctx) => MockResult | Promise<MockResult>) => async (c: Ctx) => {
    await delay(latency)
    return respond(await fn(c))
  }
  const s = (v: string | readonly string[] | undefined) => String(v ?? '')

  return [
    http.get(p('/auth/session'), open(() => mock.getSession())),
    http.post(p('/auth/login'), open(async ({ request }) => mock.login(await json(request)))),
    http.post(p('/auth/setup'), open(async ({ request }) => mock.setup(await json(request)))),
    http.post(p('/auth/logout'), guarded(() => mock.logout())),

    // Proposed live stream (not yet in lab-dashboard.openapi.yaml): topic-named events, `health` with a full body.
    // Only where EventSource exists (browser); the dashboard falls back to polling elsewhere.
    ...(typeof EventSource === 'undefined' ? [] : [sse(p('/events/stream'), ({ client }) => {
      if (mock.guard('GET', null)) {
        client.error()
        return
      }
      let n = 0
      const tick = setInterval(() => {
        try {
          client.send({ event: 'health', data: JSON.stringify(mock.health().body) } as never)
          // Every few seconds: tell the dashboard that slower topics may have changed.
          if (++n % 3 === 0) for (const topic of ['withdrawals', 'bundles', 'proposals', 'log', 'network']) client.send({ event: topic, data: '{}' } as never)
        }
        catch {
          clearInterval(tick) // stream closed by the page
        }
      }, 2500)
    })]),

    http.get(p('/health'), guarded(() => mock.health())),
    http.get(p('/patterns'), guarded(({ q }) => mock.listPatterns(q))),
    http.get(p('/patterns/:id'), guarded(({ params }) => mock.getPattern(s(params.id)))),
    http.get(p('/signals'), guarded(({ q }) => mock.listSignals(q))),

    http.get(p('/proposals'), guarded(({ q }) => mock.listProposals(q))),
    http.post(p('/proposals'), guarded(async ({ request }) => mock.createProposal(await json(request)))),
    http.get(p('/proposals/:id'), guarded(({ params }) => mock.getProposal(s(params.id)))),
    http.patch(p('/proposals/:id'), guarded(async ({ request, params }) => mock.updateProposal(s(params.id), await json(request)))),
    http.post(p('/proposals/:id/evidence'), guarded(async ({ request, params }) => mock.addEvidence(s(params.id), await json(request)))),
    http.post(p('/proposals/:id/approve'), guarded(async ({ request, params }) => mock.approve(s(params.id), await json(request)))),
    http.post(p('/proposals/:id/reject'), guarded(async ({ request, params }) => mock.reject(s(params.id), await json(request)))),

    http.get(p('/bundles'), guarded(({ q }) => mock.listBundles(q))),
    http.post(p('/bundles'), guarded(async ({ request }) => mock.assembleBundle(await json(request)))),
    http.get(p('/bundles/:version'), guarded(({ params }) => mock.getBundle(Number(params.version)))),
    http.post(p('/bundles/:version/cosign'), guarded(async ({ request, params }) => mock.cosignBundle(Number(params.version), await json(request)))),

    http.get(p('/withdrawals'), guarded(({ q }) => mock.listWithdrawals(q))),
    http.post(p('/withdrawals'), guarded(async ({ request }) => mock.createWithdrawal(await json(request)))),
    http.post(p('/emergency-stop'), guarded(async ({ request }) => mock.emergencyStop(await json(request)))),
    http.post(p('/withdrawals/:seq/cosign'), guarded(async ({ request, params }) => mock.cosign(Number(params.seq), await json(request)))),

    http.get(p('/relays'), guarded(() => mock.relays())),
    http.get(p('/peers'), guarded(() => mock.peers())),

    http.get(p('/log'), guarded(({ q }) => mock.listLog(q))),
    http.get(p('/log/:index'), guarded(({ params }) => mock.getLogEntry(Number(params.index)))),

    http.get(p('/issuers'), guarded(() => mock.issuers())),
    http.patch(p('/issuers/:id'), guarded(async ({ request, params }) => mock.updateIssuer(s(params.id), await json(request)))),
    http.post(p('/issuers/:id/revoke'), guarded(async ({ request, params }) => mock.revokeIssuer(s(params.id), await json(request)))),
    http.get(p('/clients'), guarded(({ q }) => mock.listClients(q))),
    http.patch(p('/clients/:keyid'), guarded(async ({ request, params }) => mock.updateClient(s(params.keyid), await json(request)))),
    http.post(p('/clients/:keyid/revoke'), guarded(async ({ request, params }) => mock.revokeClient(s(params.keyid), await json(request)))),

    http.get(p('/settings'), guarded(() => mock.settings())),
    http.patch(p('/settings'), guarded(async ({ request }) => mock.updateSettings(await json(request)))),

    http.all(p('/*'), open(({ request }) => ({ status: 404, body: { type: 'about:blank', title: 'Nicht gefunden', status: 404, code: 'not_found', detail: `Kein Mock für ${request.method} ${new URL(request.url).pathname}` } }))),
  ]
}
