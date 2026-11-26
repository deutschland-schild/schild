//go:build !release

// Command genvectors writes the golden vectors (contracts/vectors) and the
// test key file (contracts/testkeys/keys.json). Output is deterministic:
// fixed seeds, fixed clock, Ed25519 signatures are deterministic.
//
//	go run ./cmd/genvectors -out ../contracts
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/dsse"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/testkeys"
	"github.com/deutschland-schild/schild/contract/vectors"
)

// Now is the fixed clock of all vectors.
var Now = time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

// defaultTrust is every test key except "evil".
var defaultTrust = []string{"site-a", "site-b", "site-c", "lab-a", "lab-a2", "lab-b", "lab-c", "lab-d"}

type gen struct {
	out     string
	counter map[string]int
	written []string
}

func main() {
	out := flag.String("out", "../contracts", "contracts directory")
	flag.Parse()
	g := &gen{out: *out, counter: map[string]int{}}
	vdir := filepath.Join(*out, "vectors")
	// Remove old generated vectors (only the per-contract valid/invalid dirs).
	// The vectors of handKept contracts are written by hand, not by this
	// program: removing them would drop them from contracts-test unnoticed.
	handKept := map[string]bool{"human-check": true}
	entries, _ := os.ReadDir(vdir)
	for _, e := range entries {
		if e.IsDir() && !handKept[e.Name()] {
			for _, sub := range []string{"valid", "invalid"} {
				_ = os.RemoveAll(filepath.Join(vdir, e.Name(), sub))
			}
		}
	}
	if err := os.MkdirAll(filepath.Join(*out, "testkeys"), 0o755); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(*out, "testkeys", "keys.json"), append(testkeys.JSON(), '\n'), 0o644); err != nil {
		log.Fatal(err)
	}
	genEnvelope(g)
	genSignal(g)
	genFeedback(g)
	genAck(g)
	genSubmission(g)
	genCheckpoint(g)
	genBundle(g)
	genWithdrawal(g)
	genStream(g)
	genEvents(g)
	genSiteConfig(g)
	genLabConfig(g)
	genResults(g)
	genSecLang(g)
	genLogTree(g)
	genPeerRequest(g)
	// v0.3 (host-check.md): appended last so earlier vectors keep their numbers.
	genSiteConfigV03(g)
	genHostReport(g)
	genAgentReport(g)
	genAgentEnrolment(g)
	genAgentAck(g)
	// v0.4 (MVP-17): appended after v0.3.
	genSiteConfigV04(g)
	genEventsV04(g)
	genSiteConfigV04Distributed(g)
	genEventsV04Distributed(g)
	// v0.4 (MVP-19): appended after MVP-18.
	genSiteConfigV04Standalone(g)
	// v0.4 (MVP-21): appended after MVP-19.
	genSiteConfigV04Monitoring(g)
	// v0.4 addendum (2026-10-28): WAF evaluation keys, behaviour reason learning.
	genV04Addendum(g)
	// v0.4 (MVP-21): agent API.
	genSiteConfigV04AgentAPI(g)
	// v0.5 (MVP-22, D35): request ring, bots, geo; bot catalogue, bot
	// matching and geo field mapping.
	genSiteConfigV05(g)
	genBotCatalogue(g)
	genBotMatch(g)
	genGeoMap(g)
	// v0.5 (D36): website derivation, host resolution and status rules.
	genSiteConfigV05Websites(g)
	genWebsiteDerive(g)
	genWebsiteStatus(g)
	genWebsiteException(g)
	// D29 amendment (2026-10-29): block ladder per net class.
	genEventsV05Ladder(g)
	// D36 amendment (2026-10-29): visitors are people; own hosts are _intern.
	genWebsiteVisitor(g)
	genWebsiteDeriveOwnHosts(g)
	// D37 (2026-10-29, MVP-23 step 1): the waiting page.
	genSiteConfigV05WaitingPage(g)
	genWaitingPage(g)
	// D38 (2026-10-29): storage bounds and log hygiene.
	genStorageBounds(g)
	genHostReportV05Logs(g)
	genEventsV05D38(g)
	genWebsiteStatusD38(g)
	// Initiator decisions 2026-10-29 evening: ingress order rule (D31
	// amendment) and re-checked requests (D33 amendment).
	genIngressOrder(g)
	genRequestRecheck(g)
	genEventsRecheck(g)
	// D39 (2026-10-30, MVP-26): the CrowdSec Hub source.
	genCrowdsecHub(g)
	// D41 and D42 (2026-10-30): body limits, agent block writes.
	genD41D42(g)
	// D44 (2026-10-30): bodies waiting for the backend, the multipart class.
	genD44(g)
	genEventsD51(g)
	genD45(g)
	genD46(g)
	genSiteConfigD52(g)
	genEventsD54(g)
	// D56 (2026-11-02, MVP-14 step 1): the access lock.
	genAccessGate(g)
	genEventsD56(g)
	// D57 (2026-11-02, MVP-29): crawler control.
	genCrawlerPolicy(g)
	genEventsD57(g)
	// D63 (2026-11-04): real paths in the request ring by default.
	genSiteConfigD63(g)
	// D69 (2026-11-06): request hosts as Caddy reads them.
	genWebsiteDeriveD69(g)
	// D70 (2026-11-06): a protected path covers what lies below it.
	genAccessGateD70(g)
	// D73 (2026-11-06): rule repositories, one rule effect.
	genRuleEffect(g)
	genSiteConfigD73(g)
	genEventsD73(g)
	// D76 (2026-11-10): Host check of the dashboard.
	genSiteConfigD76(g)
	// D84 (2026-11-12): rule exceptions from the dashboard.
	genEventsD84(g)
	// D88 (2026-11-18): addresses blocked by hand in the dashboard.
	genEventsD88(g)
	genSiteConfigD89(g)
	// D92 (2026-11-19): no browser check, recommended scenario modes.
	genSiteConfigD92(g)
	// D95 (2026-11-19): preset limits switched one by one.
	genSiteConfigD95(g)
	// D105 (MVP-27): the records of a group of gateways.
	genClusterRecord(g)
	// Draft (MVP-36): the audit log.
	genAudit(g)
	genSiteConfigD103(g)
	g.summary()
}

func dirName(c string) string { return strings.ReplaceAll(c, "/", "-") }

func (g *gen) add(c, name string, valid bool, code contract.Code, desc string, ctx vectors.Context, raw []byte, decoded any) {
	g.addResult(c, name, valid, code, desc, ctx, raw, decoded, nil)
}

// addResult writes a vector; result (v0.5 classifier vectors) is the
// expected result of a valid input.
func (g *gen) addResult(c, name string, valid bool, code contract.Code, desc string, ctx vectors.Context, raw []byte, decoded, result any) {
	sub := "invalid"
	if valid {
		sub = "valid"
	}
	key := c + "/" + sub
	g.counter[key]++
	if ctx.Now == "" {
		ctx.Now = Now.Format("2006-01-02T15:04:05Z")
	}
	v := vectors.Vector{
		Contract:    c,
		Description: desc,
		Context:     ctx,
		InputRaw:    string(raw),
		Expect:      vectors.Expect{Valid: valid, Error: string(code)},
	}
	if result != nil {
		v.Expect.Result = mustJSON(result)
	}
	if decoded != nil {
		b, err := jsonx.Marshal(decoded)
		if err != nil {
			log.Fatal(err)
		}
		v.InputDecoded = b
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		log.Fatal(err)
	}
	p := filepath.Join(g.out, "vectors", dirName(c), sub, fmt.Sprintf("%03d-%s.json", g.counter[key], name))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(p, buf.Bytes(), 0o644); err != nil {
		log.Fatal(err)
	}
	g.written = append(g.written, p)
}

// retire keeps the number of a vector whose feature was removed (D72): the
// number stays unused, so every later vector keeps its file name.
func (g *gen) retire(c string, valid bool) {
	sub := "invalid"
	if valid {
		sub = "valid"
	}
	g.counter[c+"/"+sub]++
}

func (g *gen) valid(c, name, desc string, ctx vectors.Context, raw []byte, decoded any) {
	g.add(c, name, true, "", desc, ctx, raw, decoded)
}

func (g *gen) invalid(c, name string, code contract.Code, desc string, ctx vectors.Context, raw []byte, decoded any) {
	g.add(c, name, false, code, desc, ctx, raw, decoded)
}

func (g *gen) summary() {
	keys := make([]string, 0, len(g.counter))
	for k := range g.counter {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("%-28s %3d\n", k, g.counter[k])
	}
	fmt.Printf("total %d vectors\n", len(g.written))
}

// ---- helpers ----

func ctxDefault() vectors.Context {
	return vectors.Context{Trust: append([]string(nil), defaultTrust...)}
}

func ts(d time.Duration) string { return Now.Add(d).Format("2006-01-02T15:04:05Z") }

// uuid derives a deterministic v4 UUID from a name.
func uuid(name string) string {
	h := sha256.Sum256([]byte("schild/vector-uuid/" + name))
	b := h[:16]
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	s := hex.EncodeToString(b)
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:32]
}

func mustJSON(v any) []byte {
	b, err := jsonx.Marshal(v)
	if err != nil {
		log.Fatal(err)
	}
	return b
}

// toMap deep-copies a value into generic JSON (map[string]any ...).
func toMap(v any) map[string]any {
	var m map[string]any
	d := json.NewDecoder(bytes.NewReader(mustJSON(v)))
	d.UseNumber()
	if err := d.Decode(&m); err != nil {
		log.Fatal(err)
	}
	return m
}

func sign(payloadType string, payload []byte, signers ...string) *dsse.Envelope {
	var ss []dsse.Signer
	for _, s := range signers {
		ss = append(ss, testkeys.Signer(s))
	}
	env, err := dsse.Sign(payloadType, payload, ss...)
	if err != nil {
		log.Fatal(err)
	}
	return env
}

func envBytes(e *dsse.Envelope) []byte {
	b, err := e.Marshal()
	if err != nil {
		log.Fatal(err)
	}
	return b
}

// signed returns raw envelope bytes of kind signed by signers.
func signed(kind contract.Kind, payload []byte, signers ...string) []byte {
	return envBytes(sign(kind.PayloadType(), payload, signers...))
}

// decodedOf returns the payload as generic JSON for input_decoded (or the
// raw payload string when it is not JSON).
func decodedOf(payload []byte) any {
	var v any
	if err := json.Unmarshal(payload, &v); err != nil {
		return map[string]any{"payload_text": string(payload)}
	}
	return map[string]any{"payload": v}
}

func clone(m map[string]any) map[string]any { return toMap(m) }

// set sets a dotted path in a generic map.
func set(m map[string]any, path string, v any) map[string]any {
	parts := strings.Split(path, ".")
	cur := m
	for _, p := range parts[:len(parts)-1] {
		cur = cur[p].(map[string]any)
	}
	cur[parts[len(parts)-1]] = v
	return m
}
