// Package apispec checks the dashboard OpenAPI documents in contracts/api:
// every $ref resolves, operation ids are unique, every component schema
// compiles as JSON Schema 2020-12 (OpenAPI 3.1), and every fixture in
// contracts/api/fixtures validates against the success response of the
// operation named by its file name (<operationId>[.variant].json, contracts
// v0.1; variants starting with "problem" are Problem documents). The checks
// live in the tests.
package apispec

// Docs lists the API documents and their fixture directories.
var Docs = map[string]string{
	"client-dashboard.openapi.yaml": "client",
	"lab-dashboard.openapi.yaml":    "lab",
	"gateway-agent.openapi.yaml":    "agent", // v0.4 (MVP-21, D33)
}
