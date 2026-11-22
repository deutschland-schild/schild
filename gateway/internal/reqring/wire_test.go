package reqring

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

// wireSample makes n requests as a website sees them: a few hosts and user
// agents, many clients and paths.
func wireSample(n int) []Entry {
	rnd := rand.New(rand.NewSource(27))
	uas := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
		"curl/8.9.1",
	}
	hosts := []string{"shop.example", "verein.example", "blog.example"}
	rows := make([]Entry, n)
	t := int64(1795000000000)
	for i := range rows {
		t += int64(rnd.Intn(3))
		h := hosts[rnd.Intn(len(hosts))]
		id := rnd.Intn(5000)
		e := Entry{T: t, Seq: uint64(1000 + i), Client: netip.AddrFrom4([4]byte{203, 0, byte(rnd.Intn(255)), byte(rnd.Intn(255))}), Site: h, Host: h,
			RawPath: fmt.Sprintf("/produkte/%d/bild-%d.jpg", id, rnd.Intn(9)), Template: "/produkte/{n}/{slug}", UA: uas[rnd.Intn(len(uas))],
			Status: 200, BytesOut: uint32(rnd.Intn(200000)), ASN: 3320, Country: [2]byte{'D', 'E'}, NetClass: 0, UAClass: 1, Browser: 2, OS: 3, Device: 1, Dur: uint8(rnd.Intn(40)),
			PageView: rnd.Intn(4) == 0}
		switch rnd.Intn(20) {
		case 0:
			e.Referrer = "https://www.example.org/suche"
		case 1:
			e.Client = netip.MustParseAddr("2001:db8::17")
		case 2:
			e.Status, e.Outcome, e.Score, e.NRules, e.EventID = 403, OutBlockedWAF, 15, 2, "0195f3c2-7b1e-7c3a-9d11-5a4b3c2d1e0f"
			e.Rules[0], e.Rules[1] = "942100", "949110"
			e.Pin = true
		case 3:
			e.RawPath = e.Template
		}
		rows[i] = e
	}
	return rows
}

func TestWireKeepsEveryField(t *testing.T) {
	rows := wireSample(3000)
	// Every field once with a value of its own.
	rows[0] = Entry{T: 5, Seq: 9, Client: netip.MustParseAddr("192.0.2.7"), Site: "s", Host: "h", RawPath: "/p", Template: "/t", Referrer: "r", UA: "u", EventID: "e",
		Rules: [3]string{"1", "2", "3"}, NRules: 3, Score: 65535, Status: 599, BytesOut: 1<<32 - 1, ASN: 1<<32 - 1, Country: [2]byte{'A', 'T'}, Method: 9, Outcome: 7, WBReason: 3, NetClass: 10,
		UAClass: 4, Browser: 5, OS: 6, Device: 7, BotCat: 8, Verif: 4, Bot: 65535, Dur: 255, PageView: true, Crawler: true, Pin: true}
	b := AppendEntries(nil, rows)
	got, err := ReadEntries(b, len(rows))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, rows) {
		for i := range rows {
			if !reflect.DeepEqual(got[i], rows[i]) {
				t.Fatalf("entry %d:\n got %+v\nwant %+v", i, got[i], rows[i])
			}
		}
	}
	js, _ := json.Marshal(rows)
	t.Logf("%d requests: %d bytes as JSON (%d each), %d bytes as a block (%d each)", len(rows), len(js), len(js)/len(rows), len(b), len(b)/len(rows))
}

func TestWireLeavesOutAnErasedEntry(t *testing.T) {
	rows := wireSample(10)
	rows[4].Client = netip.Addr{}
	got, err := ReadEntries(AppendEntries(nil, rows), 10)
	if err != nil || len(got) != 9 {
		t.Fatalf("got %d entries, err %v; want 9", len(got), err)
	}
}

// What a member sends is input from outside: a block that is cut short,
// lies about its size or breaks a bound is refused as a whole, and no input
// makes the reader panic or read on.
func TestWireRefusesABadBlock(t *testing.T) {
	rows := wireSample(50)
	b := AppendEntries(nil, rows)
	if _, err := ReadEntries(b, 49); err == nil {
		t.Error("a block with more entries than asked for was taken")
	}
	for cut := 0; cut < len(b); cut++ {
		if _, err := ReadEntries(b[:cut], 50); err == nil {
			t.Fatalf("a block cut at %d of %d bytes was taken", cut, len(b))
		}
	}
	if _, err := ReadEntries(append(append([]byte(nil), b...), 0), 50); err == nil {
		t.Error("a block with a byte after its end was taken")
	}
	// A count the bytes cannot hold must not make the reader allocate for it.
	if _, err := ReadEntries([]byte{0xff, 0xff, 0xff, 0xff, 0x07}, 1<<30); err == nil {
		t.Error("a block that claims more entries than it has bytes was taken")
	}
	rnd := rand.New(rand.NewSource(1))
	for i := 0; i < 20000; i++ {
		c := append([]byte(nil), b...)
		for j := 0; j < 1+rnd.Intn(4); j++ {
			c[rnd.Intn(len(c))] = byte(rnd.Intn(256))
		}
		got, err := ReadEntries(c, 50)
		if err == nil {
			for k := range got {
				e := &got[k]
				if len(e.Host) > WireMaxText || len(e.RawPath) > WireMaxText || len(e.UA) > WireMaxText || int(e.NRules) > len(e.Rules) {
					t.Fatalf("a changed block gave an entry outside the bounds: %+v", e)
				}
			}
		}
	}
}

// Requests of another node are handed over by a caller that may wait: none
// is dropped while the writer is behind, they use the lower half of the
// queue only, and what did not fit in time is reported, so the caller asks
// for it again.
func TestAddForeignWaitNeverDropsAndLeavesRoomForOwnRequests(t *testing.T) {
	r, err := New(Config{StoragePath: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	rows := wireSample(ChanSize)
	// The writer does not run: the queue fills to its half and no further.
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	placed := r.AddForeignWait(ctx, rows)
	cancel()
	if placed != ChanSize/2 {
		t.Fatalf("with a writer that stands still %d requests were handed over, want %d (half the queue)", placed, ChanSize/2)
	}
	if waiting, _ := r.Backlog(); waiting != ChanSize/2 {
		t.Fatalf("%d requests wait, want %d", waiting, ChanSize/2)
	}
	// The other half is free for what this node serves itself.
	for i := 0; i < ChanSize/2; i++ {
		r.Add(&rows[i])
	}
	if r.Dropped() != 0 {
		t.Fatalf("%d own requests were dropped although the upper half of the queue was free", r.Dropped())
	}
	// With the writer running the rest goes through, in full.
	r.Start(context.Background())
	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	rest := rows[placed:]
	if got := r.AddForeignWait(ctx, rest); got != len(rest) {
		t.Fatalf("with the writer running %d of %d requests were handed over", got, len(rest))
	}
	r.Flush()
	if r.Dropped() != 0 {
		t.Fatalf("%d requests were dropped", r.Dropped())
	}
}

// BenchmarkTransfer moves requests from the served log of one ring into
// another ring, as two nodes of a group do: read after a cursor, encode,
// decode, hand over to the writer, until everything is written. "json" is
// the form of the build before (2 000 a call), "block" the compact one
// (4 096 a call).
func BenchmarkTransfer(b *testing.B) {
	for _, form := range []string{"json", "block"} {
		b.Run(form, func(b *testing.B) {
			src, err := New(Config{StoragePath: b.TempDir()})
			if err != nil {
				b.Fatal(err)
			}
			defer src.Close()
			dst, err := New(Config{StoragePath: b.TempDir()})
			if err != nil {
				b.Fatal(err)
			}
			defer dst.Close()
			const n = 16000
			src.Tee(n, 64<<20)
			rows := wireSample(n)
			for i := range rows {
				rows[i].T = time.Now().UnixMilli()
				src.Add(&rows[i])
			}
			dst.Start(context.Background())
			first := src.ServedNext() - n
			ctx := context.Background()
			var wire int64
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				after := first - 1
				for moved := 0; moved < n; {
					var got []Entry
					if form == "json" {
						part, _, next := src.Served(after, 2000, 1<<20)
						raw, _ := json.Marshal(part)
						wire += int64(len(raw))
						_ = json.Unmarshal(raw, &got)
						after = next
					} else {
						part, _, next := src.Served(after, 4096, 2<<20)
						raw := AppendEntries(nil, part)
						wire += int64(len(raw))
						got, _ = ReadEntries(raw, 4096)
						after = next
					}
					if len(got) == 0 {
						b.Fatal("the served log gave nothing")
					}
					moved += dst.AddForeignWait(ctx, got)
				}
				dst.Flush()
			}
			b.StopTimer()
			total := float64(b.N) * n
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/total, "ns/request")
			b.ReportMetric(float64(wire)/total, "bytes/request")
			b.ReportMetric(total/b.Elapsed().Seconds(), "requests/s")
		})
	}
}

func BenchmarkWire(b *testing.B) {
	rows := wireSample(2000)
	js, _ := json.Marshal(rows)
	blk := AppendEntries(nil, rows)
	b.Run("encode/json", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(js)))
		for i := 0; i < b.N; i++ {
			_, _ = json.Marshal(rows)
		}
		b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(len(rows)), "ns/request")
		b.ReportMetric(float64(len(js))/float64(len(rows)), "bytes/request")
	})
	b.Run("encode/block", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(blk)))
		buf := make([]byte, 0, len(blk))
		for i := 0; i < b.N; i++ {
			buf = AppendEntries(buf[:0], rows)
		}
		b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(len(rows)), "ns/request")
		b.ReportMetric(float64(len(blk))/float64(len(rows)), "bytes/request")
	})
	b.Run("decode/json", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			var out []Entry
			_ = json.Unmarshal(js, &out)
		}
		b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(len(rows)), "ns/request")
	})
	b.Run("decode/block", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, _ = ReadEntries(blk, len(rows))
		}
		b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(len(rows)), "ns/request")
	})
}
