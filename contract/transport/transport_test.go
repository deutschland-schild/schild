//go:build !release

package transport

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/auth"
	"github.com/deutschland-schild/schild/contract/dsse"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/contract/testkeys"
	"github.com/deutschland-schild/schild/contract/verify"
)

func signal(now time.Time) []byte {
	b, _ := jsonx.Marshal(msg.Signal{
		Schema: msg.SchemaSignal, ID: msg.NewID(), Kind: "tip", TimeBucket: msg.TimeBucket(now, 5), ActionSig: "sqli/rest-api",
		RequestSig: msg.RequestSig(msg.RequestShape{Method: "GET", PathTemplate: "/api/items/{n}", ParamNames: []string{"q"}}),
		WAFRules:   []int{942100}, Score: 80, Category: "sql-injection",
		Origin: msg.Origin{Country: "DE", ASN: 64496, NetClass: "hosting", Attribution: "tcp_peer"},
		Agent:  msg.Agent{Family: "sqlmap", Major: 1, Bot: true},
	})
	return b
}

// End to end over the interfaces: client seals with the site key, posts over
// HTTPS, a fake lab opens with the site-key authenticator and answers with a
// signed ack, the client verifies the ack.
func TestSubmitRoundTrip(t *testing.T) {
	now := time.Now().UTC()
	labTrust := testkeys.TrustStore("site-a")
	clientTrust := testkeys.TrustStore("lab-a")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != SubmitPath || r.Method != http.MethodPost {
			http.Error(w, "no", 404)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var sub struct {
			RequestID string            `json:"request_id"`
			Envelopes []json.RawMessage `json:"envelopes"`
		}
		_ = json.Unmarshal(body, &sub)
		ack := msg.Ack{Schema: msg.SchemaAck, Lab: "lab-a", IssuedAt: msg.FormatTime(time.Now()), InReplyTo: sub.RequestID,
			Accepted: []string{}, Duplicate: []string{}, Rejected: []msg.Rejected{}, Control: msg.Control{MaxBatch: 64, Reason: "ok"}}
		for _, e := range sub.Envelopes {
			res, sender, err := auth.SiteKeyAuthenticator{}.Open(r.Context(), contract.KindSignal, e, "", &verify.Context{Now: time.Now(), Trust: labTrust})
			if err != nil {
				ack.Rejected = append(ack.Rejected, msg.Rejected{ID: msg.NilID, Reason: string(contract.CodeOf(err))})
				continue
			}
			if sender.Issuer != "issuer-test-1" {
				t.Errorf("issuer %q", sender.Issuer)
			}
			ack.Accepted = append(ack.Accepted, res.Value.(*msg.Signal).ID)
		}
		p, _ := jsonx.Marshal(ack)
		env, _ := dsse.Sign(contract.KindAck.PayloadType(), p, testkeys.Signer("lab-a"))
		b, _ := env.Marshal()
		w.Header().Set("Content-Type", ContentTypeJSON)
		_, _ = w.Write(b)
	}))
	defer srv.Close()

	signer := auth.NewSiteKeySigner(testkeys.Signer("site-a"))
	sealed, err := signer.Seal(context.Background(), contract.KindSignal, signal(now))
	if err != nil {
		t.Fatal(err)
	}
	envBytes, _ := sealed.Envelope.Marshal()
	evil, _ := dsse.Sign(contract.KindSignal.PayloadType(), signal(now), testkeys.Signer("evil"))
	evilBytes, _ := evil.Marshal()
	sub := &msg.Submission{RequestID: msg.NewID(), Envelopes: []json.RawMessage{envBytes, evilBytes}}

	tr := NewHTTPS(2 * time.Second)
	tr.Client = srv.Client()
	resp, err := tr.Submit(context.Background(), Lab{ID: "lab-a", Endpoint: srv.URL}, sub, "")
	if err != nil {
		t.Fatal(err)
	}
	res, err := verify.Signed(contract.KindAck, resp.AckEnvelope, &verify.Context{Now: time.Now(), Trust: clientTrust, ExpectedInReplyTo: sub.RequestID})
	if err != nil {
		t.Fatal(err)
	}
	a := res.Value.(*msg.Ack)
	if len(a.Accepted) != 1 || len(a.Rejected) != 1 || a.Rejected[0].Reason != "signature" {
		t.Fatalf("ack %+v", a)
	}
}

func TestRefusedAndTimeout(t *testing.T) {
	// Port 1 on loopback: nobody listens there. A port the kernel just
	// handed out and that was closed again may belong to somebody else by
	// the time the request goes out.
	const addr = "127.0.0.1:1"
	tr := NewHTTPS(time.Second)
	_, err := tr.Submit(context.Background(), Lab{ID: "x", Endpoint: "http://" + addr}, &msg.Submission{RequestID: msg.NewID()}, "")
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("want ErrRefused, got %v", err)
	}
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(300 * time.Millisecond) }))
	defer slow.Close()
	tr = NewHTTPS(50 * time.Millisecond)
	_, err = tr.Submit(context.Background(), Lab{ID: "x", Endpoint: slow.URL}, &msg.Submission{RequestID: msg.NewID()}, "")
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("want ErrTimeout, got %v", err)
	}
	if _, err := tr.Submit(context.Background(), Lab{ID: "x", Endpoint: "http://lab.example"}, &msg.Submission{}, ""); err == nil {
		t.Fatal("plain http to a remote lab accepted")
	}
}

func TestV1Stubs(t *testing.T) {
	if _, err := (&OHTTP{}).Submit(context.Background(), Lab{}, nil, ""); !errors.Is(err, ErrNotV1Yet) {
		t.Fatal("ohttp stub")
	}
	if _, err := (auth.TokenSigner{}).Seal(context.Background(), contract.KindSignal, nil); !errors.Is(err, auth.ErrNotImplemented) {
		t.Fatal("token stub")
	}
	if _, _, err := (auth.TokenAuthenticator{}).Open(context.Background(), contract.KindSignal, nil, "", nil); !errors.Is(err, auth.ErrNotImplemented) {
		t.Fatal("token stub")
	}
	if _, err := auth.NewSiteKeySigner(testkeys.Signer("site-a")).Seal(context.Background(), contract.KindBundle, []byte("{}")); err == nil {
		t.Fatal("site key signed a bundle")
	}
}

func TestEndpointAllowed(t *testing.T) {
	for ep, want := range map[string]bool{
		"https://lab.example":                true,
		"https://lab.example:7443/":          true,
		"http://127.0.0.1:8443":              true,
		"http://lab.example":                 false,
		"http://127.0.0.1.lab.example":       false, // a prefix match took this as loopback
		"http://127.0.0.1@lab.example":       false, // userinfo: the host is lab.example
		"https://user:secret@lab.example":    false,
		"ftp://lab.example":                  false,
		"https://":                           false,
		"lab.example":                        false,
		"http://[::ffff:127.0.0.1]:8443/x":   false,
		"HTTPS://lab.example/with/base/path": true,
	} {
		if got := endpointAllowed(ep); got != want {
			t.Errorf("%s: %v, want %v", ep, got, want)
		}
	}
}

func TestRetryAfter(t *testing.T) {
	for v, want := range map[string]time.Duration{
		"":                              0,
		"5":                             5 * time.Second,
		"0":                             0,
		"600":                           MaxRetryAfter,
		"99999999":                      MaxRetryAfter,
		"99999999999999999999":          0,
		"-5":                            0,
		"+5":                            0,
		"1.5":                           0,
		"1h":                            0,
		"Wed, 21 Oct 2026 07:28:00 GMT": 0,
	} {
		if got := parseRetryAfter(v); got != want {
			t.Errorf("%q: %v, want %v", v, got, want)
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "86400")
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	resp, err := NewHTTPS(time.Second).Submit(context.Background(), Lab{ID: "x", Endpoint: srv.URL}, &msg.Submission{RequestID: msg.NewID()}, "")
	if err != nil || resp.RetryAfter != MaxRetryAfter {
		t.Fatalf("resp %+v, err %v", resp, err)
	}
}
