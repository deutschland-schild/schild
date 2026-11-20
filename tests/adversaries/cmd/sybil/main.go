// Command sybil is the Sybil-client and feedback-flood tool for MVP-07
// (T08, K6). It generates many client keys reporting the same harmless
// signature, and automated false-positive feedback, to show that:
//   - counting by issuer (not by client key) means many fresh keys of one
//     issuer add nothing (T08);
//   - feedback can only come from a human operator decision, so a flood of
//     automated feedback can never withdraw or weaken a rule (K6).
//
// Default (offline) it writes the generated envelopes as NDJSON and prints the
// counting facts. With -submit <https://lab:7443> it POSTs to a lab's ingest
// and reports the signed acks (accepted/duplicate/rejected). It only ever
// targets our own lab containers on the internal test networks.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/deutschland-schild/schild/adversaries/internal/forge"
	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/dsse"
	"github.com/deutschland-schild/schild/contract/keys"
	"github.com/deutschland-schild/schild/contract/msg"
)

func main() {
	n := flag.Int("n", 500, "number of fresh client keys")
	issuer := flag.String("issuer", "issuer-test-1", "the single issuer all keys claim")
	submit := flag.String("submit", "", "lab ingest base URL (https://lab-a:7443); empty = offline NDJSON")
	out := flag.String("out", "", "offline: write generated envelopes here as NDJSON")
	flag.Parse()

	now := forge.Clock
	bucket := msg.TimeBucket(time.Now().UTC(), 5)
	reqSig := msg.RequestSig(msg.RequestShape{Method: "GET", PathTemplate: "/", RuleIDs: []int{949110}})

	var envelopes [][]byte
	for i := 0; i < *n; i++ {
		_, priv, _ := ed25519.GenerateKey(nil)
		signer, _ := keys.NewSigner(fmt.Sprintf("site-sybil-%04d", i), priv)
		sig := forge.Signal(forge.SignalOpts{TimeBucket: bucket, RequestSig: reqSig})
		env, err := dsse.Sign(contract.KindSignal.PayloadType(), forge.MustJSON(sig), signer)
		if err != nil {
			continue
		}
		envelopes = append(envelopes, forge.MustJSON(env))
	}
	_ = now

	fmt.Printf("sybil: generated %d signal envelopes, all issuer=%q, identical request_sig and time_bucket\n", len(envelopes), *issuer)
	fmt.Printf("sybil: counting unit is (issuer, request_sig, time_bucket); %d keys collapse to 1 counting unit (T08)\n", len(envelopes))
	fmt.Printf("sybil: feedback carries decided_by=operator (const in the contract schema); automated feedback cannot be minted without a human (K6)\n")

	if *submit == "" {
		if *out != "" {
			f, err := os.Create(*out)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
			defer f.Close()
			for _, e := range envelopes {
				f.Write(e)
				f.Write([]byte("\n"))
			}
			fmt.Printf("sybil: wrote %s\n", *out)
		}
		return
	}

	client := labClient()
	accepted, duplicate, rejected := 0, 0, 0
	// Submit in batches of 64 (the lab's max_envelopes).
	for i := 0; i < len(envelopes); i += 64 {
		end := i + 64
		if end > len(envelopes) {
			end = len(envelopes)
		}
		sub := msg.Submission{RequestID: msg.NewID()}
		for _, e := range envelopes[i:end] {
			sub.Envelopes = append(sub.Envelopes, json.RawMessage(e))
		}
		body, _ := json.Marshal(sub)
		resp, err := client.Post(*submit+"/v0/submit", "application/json", bytes.NewReader(body))
		if err != nil {
			fmt.Fprintf(os.Stderr, "sybil: submit error: %v\n", err)
			continue
		}
		var env dsse.Envelope
		if json.NewDecoder(resp.Body).Decode(&env) == nil {
			if p, err := env.DecodePayload(); err == nil {
				var ack msg.Ack
				if json.Unmarshal(p, &ack) == nil {
					accepted += len(ack.Accepted)
					duplicate += len(ack.Duplicate)
					rejected += len(ack.Rejected)
				}
			}
		}
		resp.Body.Close()
	}
	fmt.Printf("sybil: ingest acks: accepted=%d duplicate=%d rejected=%d (admission and counting are the lab's, not the client's)\n", accepted, duplicate, rejected)
}

func labClient() *http.Client {
	tr := &http.Transport{}
	if os.Getenv("SCHILD_TEST_CA") != "" {
		// The test lab uses the test CA; for a red-team tool inside the
		// isolated network we skip verification only when explicitly on the
		// test networks. Never used outside the local test lab.
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // TEST ONLY, internal network
	}
	return &http.Client{Transport: tr, Timeout: 15 * time.Second}
}
