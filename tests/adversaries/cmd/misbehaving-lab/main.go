// Command misbehaving-lab is a lab simulator for the live red-team run
// (MVP-07). It serves the lab feed endpoints (/v0/stream, /v0/checkpoint,
// /v0/bundles/..., /v0/collecting, /v0/log) but signs everything with its own
// TEST ONLY operator key (default: the "evil" key, a distinct operator that
// honest clients do not trust). It can be followed by a relay so its output
// reaches honest clients, which must then refuse it: a single misbehaving
// operator can never reach k independent operators.
//
// MODE (env SCHILD_ADVERSARY_MODE):
//   - poison:     publish a bundle that blocks a legitimate login (T07)
//   - silent:     accept connections but publish nothing (availability)
//   - equivocate: serve different bundle content on alternating requests (T10 split view)
//   - replay:     serve an old, lower version (T11 rollback)
//
// It is only ever run on the internal test lab networks against our own
// containers. It never terminates TLS secrets of honest labs; it cannot forge
// their signatures.
package main

import (
	"log"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/deutschland-schild/schild/adversaries/internal/forge"
	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/contract/peerauth"
	"github.com/deutschland-schild/schild/contract/stream"
	"github.com/deutschland-schild/schild/contract/testkeys"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	mode := env("SCHILD_ADVERSARY_MODE", "poison")
	keyName := env("SCHILD_ADVERSARY_KEY", "evil")
	labID := env("SCHILD_ADVERSARY_LAB", "lab-mal")
	listen := env("SCHILD_ADVERSARY_LISTEN", ":7444")
	log.Printf("misbehaving-lab: mode=%s key=%s lab=%s listen=%s (signs with its own operator; honest clients must refuse it)", mode, keyName, labID, listen)

	a := &adv{mode: mode, keyName: keyName, labID: labID, epoch: "mal"}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("/v0/stream", a.stream)
	mux.HandleFunc("/v0/checkpoint", a.checkpoint)
	mux.HandleFunc("/v0/bundles/", a.bundle)
	mux.HandleFunc("/v0/collecting", a.collecting)
	srv := &http.Server{Addr: listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

type adv struct {
	mode, keyName, labID string
	epoch                string
	seq                  atomic.Uint64
	flip                 atomic.Bool
}

// version and content depend on the mode.
func (a *adv) bundlePayload() map[string]any {
	switch a.mode {
	case "replay":
		return forge.Bundle(forge.BundleOpts{Version: 1, Rules: []map[string]any{forge.RulePoison(forge.RuleID(7), 7700007, "block")}})
	case "equivocate":
		if a.flip.Swap(!a.flip.Load()) {
			return forge.Bundle(forge.BundleOpts{Version: 100, Rules: []map[string]any{forge.RulePoison(forge.RuleID(7), 7700007, "block")}})
		}
		return forge.Bundle(forge.BundleOpts{Version: 100, Rules: []map[string]any{forge.RuleObserve(forge.RuleID(8), 7700008)}})
	default: // poison
		return forge.Bundle(forge.BundleOpts{Version: 100, Rules: []map[string]any{forge.RulePoison(forge.RuleID(7), 7700007, "block")}})
	}
}

func (a *adv) signedBundle() []byte {
	return forge.SignBytes(contract.KindBundle, forge.MustJSON(a.bundlePayload()), a.keyName)
}

func (a *adv) signedCheckpoint() []byte {
	b := a.bundlePayload()
	cp := forge.Checkpoint(a.labID, a.seq.Add(1), uint64(b["version"].(uint64)), msg.Digest(forge.MustJSON(b)), 9*time.Minute)
	return forge.SignBytes(contract.KindCheckpoint, forge.MustJSON(cp), a.keyName)
}

func (a *adv) stream(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", stream.ContentType)
	fl, _ := w.(http.Flusher)
	_ = stream.WriteRetry(w, stream.RetryMS)
	if a.mode == "silent" {
		// Hold the connection open, send only keep-alives: availability attack.
		for i := 0; i < 600; i++ {
			_ = stream.WriteComment(w, "keep-alive")
			if fl != nil {
				fl.Flush()
			}
			time.Sleep(time.Second)
		}
		return
	}
	send := func(ev *stream.Event) {
		_ = stream.WriteEvent(w, ev)
		if fl != nil {
			fl.Flush()
		}
	}
	for {
		cp := a.signedCheckpoint()
		send(&stream.Event{Type: stream.TypeBundle, ID: stream.FormatID(a.epoch, a.seq.Add(1)), Envelope: a.signedBundle()})
		send(&stream.Event{Type: stream.TypeCheckpoint, ID: stream.FormatID(a.epoch, a.seq.Add(1)), Envelope: cp})
		send(&stream.Event{Type: stream.TypeHeartbeat, ID: stream.FormatID(a.epoch, a.seq.Add(1)), Relay: &stream.Relay{ID: a.labID, Time: msg.FormatTime(time.Now().UTC())}, Checkpoint: cp})
		time.Sleep(10 * time.Second)
		if r.Context().Err() != nil {
			return
		}
	}
}

func (a *adv) checkpoint(w http.ResponseWriter, r *http.Request) {
	if a.mode == "silent" {
		http.Error(w, "no checkpoint", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(a.signedCheckpoint())
}

func (a *adv) bundle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(a.signedBundle())
}

// collecting refuses everyone without a valid peer signature, like an honest
// lab (cosign.md): the request must be signed by a configured peer's rules
// key. The adversary has no honest peers configured, so every request is 401.
func (a *adv) collecting(w http.ResponseWriter, r *http.Request) {
	trust := testkeys.TrustStore() // no configured peers
	if _, err := peerauth.VerifyHTTP(r, nil, a.labID, trust, time.Now().UTC()); err != nil {
		http.Error(w, "401 unauthorized peer", http.StatusUnauthorized)
		return
	}
	w.Write([]byte(`{"lab":"` + a.labID + `","items":[]}`))
}
