package eventlog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deutschland-schild/schild/gateway/internal/store"
)

func TestNDJSONMirror(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ndjson")
	m, err := OpenNDJSONMirror(dir, 200, nil)
	if err != nil {
		t.Fatal(err)
	}
	m.Write([]*store.EventRow{
		{Type: "schild.request.evaluated.v1", Body: []byte(`{"type":"schild.request.evaluated.v1"}`)},
		{Type: "schild.block.set.v1", Body: []byte(`{"type":"schild.block.set.v1"}`)},
	})
	// Over the size cap: dropped, never partial.
	m.Write([]*store.EventRow{{Type: "schild.request.evaluated.v1", Body: []byte(strings.Repeat("x", 300))}})
	m.Close()
	ev, _ := os.ReadFile(filepath.Join(dir, "events.ndjson"))
	if strings.Count(string(ev), "\n") != 2 {
		t.Fatalf("events %q", ev)
	}
	if st, _ := os.Stat(filepath.Join(dir, "events.ndjson")); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
}
