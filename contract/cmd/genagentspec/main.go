// Command genagentspec writes contract/agentapi/openapi.json, the bundled agent
// API document the gateway serves (D61). Run from contract:
//
//	go run ./cmd/genagentspec
package main

import (
	"fmt"
	"os"

	"github.com/deutschland-schild/schild/contract/apispec"
)

func main() {
	b, err := apispec.Bundle("../contracts/api", apispec.AgentDoc)
	if err == nil {
		err = os.WriteFile("agentapi/openapi.json", b, 0o644)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "genagentspec:", err)
		os.Exit(1)
	}
}
