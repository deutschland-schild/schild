//go:build spec26measure

// TEST ONLY: MVP-26 measurement, in-process. Copied into a scratch copy of client/internal/waf, never into the product
// tree. Measures what a WAF instance costs with and without the hub rules, on the same requests in the same process.
package waf

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/deutschland-schild/schild/contract/crowdsec"
)

func m26Hub(t testing.TB) []HubRule {
	raw, err := os.ReadFile(os.Getenv("M26_SET"))
	if err != nil {
		t.Fatal(err)
	}
	var set crowdsec.Set
	if err := json.Unmarshal(raw, &set); err != nil {
		t.Fatal(err)
	}
	var out []HubRule
	for _, it := range set.Rules {
		body, _ := base64.StdEncoding.DecodeString(it.Content)
		r, sk := crowdsec.Convert(it.Name, it.Version, it.Digest, body, it.Description)
		if sk != nil {
			continue
		}
		out = append(out, HubRule{Name: r.Name, Version: r.Version, BaseID: r.BaseID, Groups: r.SecLang})
	}
	return out
}

func m26Build(t testing.TB, hub []HubRule) *Instance {
	inst, err := Build(Config{CRS: true, ParanoiaLevel: 1, AnomalyThreshold: 5, BodyLimit: 13107200, ArgsLimit: 1000, Hub: hub})
	if err != nil {
		t.Fatal(err)
	}
	return inst
}

func heap() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

func TestM26Build(t *testing.T) {
	hub := m26Hub(t)
	h0 := heap()
	for i := 0; i < 5; i++ {
		t0 := time.Now()
		a := m26Build(t, nil)
		d1 := time.Since(t0)
		h1 := heap()
		t0 = time.Now()
		b := m26Build(t, hub)
		d2 := time.Since(t0)
		h2 := heap()
		t.Logf("build CRS only %v, CRS+hub %v, heap after A %d KiB, after A+B %d KiB (hub rules %d)", d1, d2, (h1-h0)/1024, (h2-h1)/1024, len(hub))
		runtime.KeepAlive(a)
		runtime.KeepAlive(b)
		a.Close()
		b.Close()
	}
	var sum strings.Builder
	n := 0
	for _, r := range hub {
		for _, g := range r.Groups {
			sum.WriteString(g)
			n++
		}
	}
	t.Logf("groups %d, SecLang bytes %d", n, sum.Len())
}

type m26Req struct {
	name, method, url, ct string
	body                  string
}

func m26Reqs() []m26Req {
	form := "_token=abc"
	for i := 0; i < 100; i++ {
		form += fmt.Sprintf("&field%d=%s", i, strings.Repeat("lorem", 8))
	}
	long := strings.Repeat("lorem ipsum dolor sit amet ", 100)
	js := `{"components":[{"snapshot":"` + long + `","updates":{"a":"b"},"calls":[{"method":"save"}]}]}`
	big := strings.Repeat("lorem ipsum dolor sit amet ", 2500)
	keys := "{"
	for i := 0; i < 500; i++ {
		keys += fmt.Sprintf(`"k%d":{"id":%d,"name":"%s"},`, i, i, strings.Repeat("x", 30))
	}
	keys += `"z":1}`
	return []m26Req{
		{"get_root", "GET", "/", "", ""},
		{"get_path", "GET", "/products/blue-shirt?color=red&size=42", "", ""},
		{"post_form_8", "POST", "/contact", "application/x-www-form-urlencoded", "a=1&b=2&c=3&d=4&e=5&f=6&g=7&h=8"},
		{"post_form_100", "POST", "/contact", "application/x-www-form-urlencoded", form},
		{"post_json_2k", "POST", "/livewire/update", "application/json", js},
		{"post_json_64k", "POST", "/livewire/update", "application/json", `{"t":"` + big + `"}`},
		{"post_json_500keys", "POST", "/api/items/bulk", "application/json", keys},
	}
}

func m26Run(b *testing.B, inst *Instance, q m26Req) {
	for i := 0; i < b.N; i++ {
		tx, _ := inst.NewTransaction()
		var rd *strings.Reader
		var r *http.Request
		if q.body != "" {
			rd = strings.NewReader(q.body)
			r = httptest.NewRequest(q.method, q.url, rd)
			r.Header.Set("Content-Type", q.ct)
		} else {
			r = httptest.NewRequest(q.method, q.url, nil)
		}
		r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0")
		r.Header.Set("Accept", "text/html,application/xhtml+xml")
		r.Host = "shop.test"
		ProcessHeaders(tx, r, "203.0.113.1", 1234)
		if q.body != "" {
			if _, _, err := ReadBodyInfo(tx, r, Limits{}); err != nil {
				b.Fatal(err)
			}
		}
		_, _ = tx.ProcessRequestBody()
		_ = inst.Analyze(tx.MatchedRules())
		tx.Close()
	}
}

func BenchmarkM26(b *testing.B) {
	hub := m26Hub(b)
	off, on := m26Build(b, nil), m26Build(b, hub)
	for _, q := range m26Reqs() {
		b.Run("off/"+q.name, func(b *testing.B) { b.ReportAllocs(); m26Run(b, off, q) })
		b.Run("hub/"+q.name, func(b *testing.B) { b.ReportAllocs(); m26Run(b, on, q) })
	}
}
