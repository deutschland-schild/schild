package crawlers

import (
	"math/rand/v2"
	"net/netip"
	"strings"
	"testing"
	"time"

	contractbots "github.com/deutschland-schild/schild/contract/bots"
	"github.com/deutschland-schild/schild/contract/config"
	cc "github.com/deutschland-schild/schild/contract/crawlers"
	"github.com/deutschland-schild/schild/gateway/internal/bots"
)

var clock = time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)

// ruleName returns the contract name of a rule of a table.
func ruleName(r uint8) string {
	names := [...]string{cc.RuleNone, cc.RuleBot, cc.RuleCategory, cc.RuleImpersonator}
	if int(r) >= len(names) {
		return cc.RuleNone
	}
	return names[r]
}

func engine(t testing.TB) *bots.Engine {
	t.Helper()
	e, err := bots.New(config.Bots{}, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func control(t testing.TB, p cc.Policy) (*Control, *Table) {
	t.Helper()
	c := New(engine(t), clock)
	st := NewState()
	st.Entries["shop.example"] = &Entry{Policy: p}
	c.Set(st)
	return c, c.Lookup("shop.example")
}

// The compiled table answers exactly what contract/crawlers.RuleFor says,
// for every catalogue bot, under random policies.
func TestTableMatchesContract(t *testing.T) {
	e := engine(t)
	rng := rand.New(rand.NewPCG(57, 2026))
	cat := e.Catalogue()
	a := netip.MustParseAddr("203.0.113.50")
	for round := 0; round < 200; round++ {
		p := cc.Policy{Categories: map[string]string{}, Bots: map[string]string{}}
		for _, c := range contractbots.Categories {
			switch rng.IntN(3) {
			case 0:
				p.Categories[c] = cc.Block
			case 1:
				p.Categories[c] = cc.Allow
			}
		}
		for i := 0; i < rng.IntN(20); i++ {
			b := cat.Bots[rng.IntN(len(cat.Bots))]
			p.Bots[b.ID] = []string{cc.Allow, cc.Block}[rng.IntN(2)]
		}
		if rng.IntN(2) == 0 {
			p.Impersonators = cc.Block
		}
		c := New(e, clock)
		st := NewState()
		st.Entries["w"] = &Entry{Policy: p}
		c.Set(st)
		tb := c.Lookup("w")
		if (tb != nil) != p.Blocks() {
			t.Fatalf("table %v, blocks %v (%+v)", tb != nil, p.Blocks(), p)
		}
		for id := 1; id <= e.NumBots(); id++ {
			b := e.Bot(uint16(id))
			want := cc.RuleFor(p, b.ID, b.Category, bots.VerificationName(e.Verify(uint16(id), a)))
			if got := ruleName(tb.Rule(uint16(id), a)); got != want {
				t.Fatalf("round %d, %s (%s): %s, want %s", round, b.ID, b.Category, got, want)
			}
		}
		if tb.Rule(0, a) != RuleNone {
			t.Fatal("no catalogue entry is never blocked")
		}
	}
}

func TestOverridePrecedence(t *testing.T) {
	e := engine(t)
	_, tb := control(t, cc.Policy{Categories: map[string]string{"ai_training": cc.Block}, Bots: map[string]string{"gptbot": cc.Allow, "bingbot": cc.Block}, Impersonators: cc.Block})
	other := netip.MustParseAddr("203.0.113.50")
	google := netip.MustParseAddr("66.249.66.1")
	for _, tc := range []struct {
		bot  string
		a    netip.Addr
		want uint8
	}{
		{"gptbot", other, RuleImpersonator}, // allowed, but outside OpenAI's ranges
		{"ccbot", other, RuleImpersonator},  // its category blocks, and it is outside its ranges
		{"claudebot", other, RuleCategory},  // no ranges: never an impersonator
		{"bingbot", other, RuleImpersonator},
		{"googlebot", google, RuleNone},
		{"googlebot", other, RuleImpersonator},
		{"chatgpt-user", other, RuleImpersonator},
	} {
		if got := tb.Rule(e.ID(tc.bot), tc.a); got != tc.want {
			t.Errorf("%s from %s: %s, want %s", tc.bot, tc.a, ruleName(got), ruleName(tc.want))
		}
	}
	_, tb = control(t, cc.Policy{Categories: map[string]string{"ai_training": cc.Block}, Bots: map[string]string{"gptbot": cc.Allow, "bingbot": cc.Block}})
	for bot, want := range map[string]uint8{"gptbot": RuleNone, "ccbot": RuleCategory, "bingbot": RuleBot, "googlebot": RuleNone} {
		if got := tb.Rule(e.ID(bot), other); got != want {
			t.Errorf("%s: %s, want %s", bot, ruleName(got), ruleName(want))
		}
	}
}

// A policy that only allows compiles to no table: the gate does nothing.
func TestNoTableWithoutBlock(t *testing.T) {
	for _, p := range []cc.Policy{{}, {Categories: map[string]string{"ai_training": cc.Allow}}, {Bots: map[string]string{"gptbot": cc.Allow}, Impersonators: cc.Allow},
		{Bots: map[string]string{"gone-from-catalogue": cc.Block}}} {
		c, tb := control(t, p)
		if tb != nil || c.Lookup("other.example") != nil {
			t.Errorf("%+v: table", p)
		}
	}
	var c *Control
	if c.Lookup("x") != nil {
		t.Error("nil control")
	}
}

func TestUnknownBotsSkipped(t *testing.T) {
	c := New(engine(t), clock)
	st := NewState()
	st.Entries["w"] = &Entry{Policy: cc.Policy{Categories: map[string]string{"ai_training": cc.Block}, Bots: map[string]string{"gone-bot": cc.Allow}}}
	if unk := c.Set(st); len(unk) != 1 || unk[0] != "gone-bot" {
		t.Fatalf("unknown %v", unk)
	}
	if c.Lookup("w") == nil {
		t.Fatal("the rest of the policy holds")
	}
	// The state in force no longer holds the id, so a change of the policy
	// passes the catalogue check; the caller's state is not changed.
	if _, ok := c.Entry("w").Policy.Bots["gone-bot"]; ok {
		t.Fatal("unknown id still in force")
	}
	if err := c.Entry("w").Policy.Check(c.Known); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.Entries["w"].Policy.Bots["gone-bot"]; !ok {
		t.Fatal("Set changed its argument")
	}
	if unk := c.Set(c.State()); unk != nil {
		t.Fatalf("pruned twice: %v", unk)
	}
}

// The cache of crawler control answers what the catalogue match answers.
func TestUACache(t *testing.T) {
	e := engine(t)
	c := New(e, clock)
	long := "Mozilla/5.0 " + strings.Repeat("a", 600) + " GPTBot/1.2"
	for _, ua := range []string{"", "Mozilla/5.0 (compatible; GPTBot/1.2)", "curl/8.5.0", "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0", long, "Googlebot-Image/1.0"} {
		want, _ := e.MatchUA(ua)
		for i := 0; i < 2; i++ { // miss, then hit
			if got := c.BotID(ua); got != want {
				t.Fatalf("%.40q: %d, want %d", ua, got, want)
			}
		}
	}
	ua := "Mozilla/5.0 (compatible; GPTBot/1.2)"
	if n := testing.AllocsPerRun(100, func() { _ = c.BotID(ua) }); n != 0 {
		t.Fatalf("%.1f allocations", n)
	}
}

// Counts survive a change of the policy and are kept per website.
func TestCountsCarryOver(t *testing.T) {
	e := engine(t)
	c, tb := control(t, cc.Policy{Categories: map[string]string{"ai_training": cc.Block}})
	id := e.ID("gptbot")
	tb.Add(id, OutBlocked)
	tb.Add(id, OutBlocked)
	tb.Add(id, OutWouldBlock)
	tb.Add(0, 7) // ignored
	st := c.State().Clone()
	st.Entries["shop.example"].Policy.Impersonators = cc.Block
	st.Entries["blog.example"] = &Entry{Policy: cc.Policy{Bots: map[string]string{"gptbot": cc.Block}}}
	c.Set(st)
	c.Lookup("shop.example").Add(id, OutBlocked)
	c.Lookup("blog.example").Add(id, OutBlocked)
	got := c.Counts("shop.example")
	if len(got) != 1 || got[0].Bot != id || got[0].Blocked != 3 || got[0].WouldBlock != 1 {
		t.Fatalf("shop counts %+v", got)
	}
	tot := c.Totals()
	if len(tot) != 1 || tot[0].Blocked != 4 || tot[0].WouldBlock != 1 {
		t.Fatalf("totals %+v", tot)
	}
	if c.Counts("none.example") != nil {
		t.Fatal("counts of a website without policy")
	}
}

func TestStateClone(t *testing.T) {
	st := NewState()
	st.Entries["w"] = &Entry{Policy: cc.Policy{Categories: map[string]string{"ai_training": cc.Block}}}
	c := st.Clone()
	c.Entries["w"].Policy.Categories["seo_tool"] = cc.Block
	if len(st.Entries["w"].Policy.Categories) != 1 {
		t.Fatal("clone shares the policy")
	}
}

func BenchmarkRule(b *testing.B) {
	e := engine(b)
	_, tb := control(b, cc.Policy{Categories: map[string]string{"ai_training": cc.Block}, Impersonators: cc.Block})
	id := e.ID("googlebot")
	a := netip.MustParseAddr("203.0.113.50")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = tb.Rule(id, a)
	}
}
