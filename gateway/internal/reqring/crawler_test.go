package reqring

import (
	"testing"

	cr "github.com/deutschland-schild/schild/contract/requests"
)

// D57: blocked_crawler and the crawler flag survive the codec; a would_block
// of the crawler policy alone is no alert, a blocked crawler is stopped.
func TestCrawlerRecord(t *testing.T) {
	if cr.Outcomes[OutBlockedCrawler] != cr.BlockedCrawler {
		t.Fatalf("index %d is %s", OutBlockedCrawler, cr.Outcomes[OutBlockedCrawler])
	}
	for _, rec := range []Rec{
		{T: 5, Site: "s", Outcome: OutBlockedCrawler, Crawler: true, HasBot: true, Bot: 42, Verif: VerifClaimed, NRules: 0},
		{T: 6, Site: "s", Outcome: OutWouldBlock, Crawler: true, HasBot: true, Bot: 42, Verif: VerifMismatch, NRules: 3, Rules: [3]string{"a", "b", "c"}},
		{T: 7, Site: "s", Outcome: OutWouldBlock, HasBot: true, Bot: 42, Verif: VerifVerified},
	} {
		b := appendRec(nil, &rec, 0, nil)
		var got Rec
		if err := decodeRec(b, 0, nil, &got); err != nil || got.Outcome != rec.Outcome || got.Crawler != rec.Crawler || got.NRules != rec.NRules || got.Bot != rec.Bot {
			t.Fatalf("%+v: %+v %v", rec, got, err)
		}
	}
	if alert(&Rec{Outcome: OutWouldBlock, Crawler: true}) || alert(&Rec{Outcome: OutBlockedCrawler, Crawler: true}) {
		t.Fatal("a crawler rule alone is no alert")
	}
	if !alert(&Rec{Outcome: OutWouldBlock}) || !alert(&Rec{Outcome: OutBlockedWAF}) {
		t.Fatal("WAF alerts stay alerts")
	}
	if !stopped(OutBlockedCrawler) || stopped(OutWouldBlock) {
		t.Fatal("stopped")
	}
	b := appendRec(nil, &Rec{T: 1, Site: "s", Outcome: OutBlockedCrawler + 1}, 0, nil)
	if err := decodeRec(b, 0, nil, &Rec{}); err == nil {
		t.Fatal("an unknown outcome is corrupt")
	}
}
