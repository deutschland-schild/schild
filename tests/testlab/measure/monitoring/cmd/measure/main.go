// Command spec21 is the MVP-21 measurement harness (TEST ONLY): a geo
// database with known networks, a backend that answers as asked, and a
// traffic replay with per-minute ground truth.
//
//	spec21 geo -out geo.mmdb -table geo.json
//	spec21 backend -listen 127.0.0.1:18099
//	spec21 replay -target http://127.0.0.1:18090 -phase mix|zipf -minutes 5 -out truth.json
//	spec21 flood -target ... -paths N -addrs N -pathlen N
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: spec21 geo|backend|replay|flood ...")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "geo":
		err = cmdGeo(os.Args[2:])
	case "backend":
		err = cmdBackend(os.Args[2:])
	case "replay":
		err = cmdReplay(os.Args[2:])
	case "sockets":
		err = cmdSockets(os.Args[2:])
	case "agentflood":
		err = cmdAgentFlood(os.Args[2:])
	case "flood":
		err = cmdFlood(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
