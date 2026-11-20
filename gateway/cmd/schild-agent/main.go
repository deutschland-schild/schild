// Command schild-agent is the Schild Agent for internal VMs behind a Schild
// Gateway (MVP-11): the read-only server check and the agent that delivers
// signed reports to the gateway. Nothing else: no proxy, no WAF, no
// dashboard, no listener (main_test.go checks the dependencies).
//
//	schild-agent enrol --gateway URL --gateway-name NAME --pin sha256:HEX --code CODE
//	schild-agent init  --gateway URL --gateway-name NAME --pin sha256:HEX [--key FILE --keyid ID]
//	schild-agent run|once [--dir DIR] [--app PATH]... [--interval 24h]
//	schild-agent status [--dir DIR]
//	schild-agent check  (the same flags and exit codes as `schild check`)
//	schild-agent version
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/deutschland-schild/schild/gateway/internal/buildinfo"
	"github.com/deutschland-schild/schild/gateway/internal/hostcli"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, hostcli.AgentUsage)
		os.Exit(2)
	}
	sub, args := os.Args[1], os.Args[2:]
	switch sub {
	case "check":
		os.Exit(hostcli.Check("schild-agent check", args))
	case "version", "-version", "--version":
		fmt.Println(strings.Replace(buildinfo.String(), "schild ", "schild-agent ", 1))
		return
	case "help", "-h", "--help":
		fmt.Fprint(os.Stdout, hostcli.AgentUsage)
		return
	case "enrol", "enroll", "init", "run", "once", "status":
	default:
		fmt.Fprint(os.Stderr, hostcli.AgentUsage)
		os.Exit(2)
	}
	if err := hostcli.Agent(sub, args, hostcli.Logger("schild-agent")); err != nil {
		fmt.Fprintln(os.Stderr, "schild-agent:", err)
		os.Exit(1)
	}
}
