package agentapi

import (
	"strings"
	"testing"

	contractapi "github.com/deutschland-schild/schild/contract/agentapi"
	"github.com/deutschland-schild/schild/contract/audit"
)

// MVP-36 (contracts/audit.md section 2): every write of the agent API is
// in an action of the audit log or in not_audited with its reason, and the
// catalogue names no agent operation that is no write of this API. The
// request test is a POST that changes nothing; it is listed too.
func TestEveryAgentWriteIsInTheAuditCatalogue(t *testing.T) {
	writes := map[string]bool{"agent:" + contractapi.OpTestRequest: true}
	for op := range contractapi.WriteOperations {
		writes["agent:"+op] = true
	}
	listed := map[string]bool{}
	for _, a := range audit.Actions.Actions {
		for _, op := range a.Operations {
			if strings.HasPrefix(op, "agent:") && op != "agent:any" {
				listed[op] = true
			}
		}
	}
	for _, o := range audit.Actions.NotAudited {
		if strings.HasPrefix(o.Operation, "agent:") {
			if listed[o.Operation] {
				t.Errorf("%s is in an action and in not_audited", o.Operation)
			}
			if o.Reason == "" {
				t.Errorf("%s is not audited without a reason", o.Operation)
			}
			if auditedWrite(strings.TrimPrefix(o.Operation, "agent:")) {
				t.Errorf("%s is not audited in the catalogue, and the server gives it an origin and a budget", o.Operation)
			}
			listed[o.Operation] = true
		}
	}
	for op := range writes {
		if !listed[op] {
			t.Errorf("%s changes something and is neither in an action nor in not_audited", op)
		}
	}
	for op := range listed {
		if !writes[op] {
			t.Errorf("the catalogue names %s, which is no write of the agent API", op)
		}
	}
	// A refused write is counted under the action it tried.
	for op := range contractapi.WriteOperations {
		if auditedWrite(op) && actionOf["agent:"+op] == "" {
			t.Errorf("a refused %s has no action", op)
		}
	}
}
