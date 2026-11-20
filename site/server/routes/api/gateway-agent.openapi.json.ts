import spec from '../../../../contract/agentapi/openapi.json'

// The agent API of the gateway (contracts/api/gateway-agent.openapi.yaml), bundled into one file by `make contracts-sync`
// and prerendered as a static file for the reference at /api. Two changes for readers, the contract stays as it is:
// - the server is the loopback address of the default configuration instead of the relative /agent/v0,
// - the title is the name the website uses, the license note without a link goes.
const AGENT_API_SERVER = 'http://127.0.0.1:8789/agent/v0'

export default defineEventHandler(() => {
  const doc = structuredClone(spec) as any
  // "see repository" without a link says nothing on the website.
  delete doc.info.license
  doc.info.title = 'Schild Gateway API'
  return { ...doc, servers: [{ url: AGENT_API_SERVER, description: 'Your gateway, on the server itself (agent_api.listen)' }] }
})
