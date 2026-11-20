package agentapi

import _ "embed"

// OpenAPI is contracts/api/gateway-agent.openapi.yaml as one JSON document with
// every reference inside it (D61), served at GET /agent/v0/openapi.json.
// `make contracts-sync` writes it; TestAgentBundle in contract/apispec fails
// when it is stale.
//
//go:embed openapi.json
var OpenAPI []byte

// OpOpenAPI serves OpenAPI.
const OpOpenAPI = "getAgentOpenAPI"
