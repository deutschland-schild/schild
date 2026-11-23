package app

import (
	"encoding/json"
	"reflect"
	"testing"
)

func sameJSON(t *testing.T, got []byte, want string) {
	t.Helper()
	var a, b any
	if err := json.Unmarshal(got, &a); err != nil {
		t.Fatalf("%s: %v", got, err)
	}
	if err := json.Unmarshal([]byte(want), &b); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Errorf("got %s, want %s", got, want)
	}
}

// Every codec: what split cuts, join puts back, and a change of one entry
// touches no other.
func TestEntryCodecs(t *testing.T) {
	// A table: rows keyed by their first columns.
	tc := tableCodec{pk: 1}
	dump := []byte(`{"columns":["id","ip"],"rows":[["al_1","203.0.113.1"],["al_2","203.0.113.2"]]}`)
	es, err := tc.split(dump)
	if err != nil || len(es) != 2 || string(es[`["al_1"]`]) != `["al_1","203.0.113.1"]` {
		t.Fatalf("table split: %v, %v", es, err)
	}
	out, err := tc.join(dump, map[string][]byte{`["al_3"]`: []byte(`["al_3","203.0.113.3"]`)}, []string{`["al_1"]`})
	if err != nil {
		t.Fatal(err)
	}
	sameJSON(t, out, `{"columns":["id","ip"],"rows":[["al_2","203.0.113.2"],["al_3","203.0.113.3"]]}`)
	// A row that is none of this table, or under another key, is left out.
	out, _ = tc.join(dump, map[string][]byte{`["x"]`: []byte(`["x"]`), `["y"]`: []byte(`["z","1.2.3.4"]`)}, nil)
	sameJSON(t, out, string(dump))
	// An empty table stays a table.
	out, _ = tc.join(dump, nil, []string{`["al_1"]`, `["al_2"]`})
	sameJSON(t, out, `{"columns":["id","ip"],"rows":[]}`)

	// The settings overlay: one entry per leaf.
	oc := objectCodec{depth: 8}
	ov := []byte(`{"retention":{"events_days":30,"summaries_days":100},"rules":{"crs":{"state":"detect"}}}`)
	es, _ = oc.split(ov)
	if len(es) != 3 || string(es[`["retention","events_days"]`]) != "30" || string(es[`["rules","crs","state"]`]) != `"detect"` {
		t.Fatalf("overlay split: %v", es)
	}
	out, _ = oc.join(ov, map[string][]byte{`["retention","events_days"]`: []byte("11"), `["behaviour","scenarios","path_probing","mode"]`: []byte(`"block"`)},
		[]string{`["rules","crs","state"]`})
	sameJSON(t, out, `{"retention":{"events_days":11,"summaries_days":100},"behaviour":{"scenarios":{"path_probing":{"mode":"block"}}}}`)
	if es, _ := oc.split(nil); len(es) != 0 {
		t.Errorf("no value has entries: %v", es)
	}
	out, _ = oc.join(nil, map[string][]byte{`["a","b"]`: []byte("1")}, nil)
	sameJSON(t, out, `{"a":{"b":1}}`)

	// The state of the websites: one entry per website, one per other field.
	sc := objectCodec{depth: 2}
	st := []byte(`{"entries":{"shop":{"policy":{"x":1}},"blog":{"policy":{"x":2}}},"prefix":"abc"}`)
	es, _ = sc.split(st)
	if len(es) != 3 || string(es[`["entries","shop"]`]) != `{"policy":{"x":1}}` || string(es[`["prefix"]`]) != `"abc"` {
		t.Fatalf("state split: %v", es)
	}
	out, _ = sc.join(st, map[string][]byte{`["entries","blog"]`: []byte(`{"policy":{"x":9}}`)}, []string{`["entries","shop"]`})
	sameJSON(t, out, `{"entries":{"blog":{"policy":{"x":9}}},"prefix":"abc"}`)

	// A list of things with an id.
	lc := listCodec{id: "id"}
	list := []byte(`[{"id":"a","limit":1},{"id":"b","limit":2}]`)
	es, _ = lc.split(list)
	if len(es) != 2 || string(es[`["a"]`]) != `{"id":"a","limit":1}` {
		t.Fatalf("list split: %v", es)
	}
	out, _ = lc.join(list, map[string][]byte{`["c"]`: []byte(`{"id":"c","limit":3}`), `["b"]`: []byte(`{"id":"b","limit":20}`)}, []string{`["a"]`})
	sameJSON(t, out, `[{"id":"b","limit":20},{"id":"c","limit":3}]`)
	out, _ = lc.join(nil, nil, nil)
	sameJSON(t, out, `[]`)

	// A value that is one piece.
	wc := wholeCodec{}
	es, _ = wc.split([]byte{1, 2, 3})
	if len(es) != 1 {
		t.Fatalf("whole split: %v", es)
	}
	if out, _ := wc.join([]byte{1}, map[string][]byte{"": {9}}, nil); string(out) != "\x09" {
		t.Errorf("whole join: %v", out)
	}
}

// Split then join of nothing is the same set of entries, for every codec.
func TestEntryCodecsRoundTrip(t *testing.T) {
	cases := []struct {
		c    entryCodec
		blob string
	}{
		{tableCodec{pk: 3}, `{"columns":["repository","rule","kind","note"],"rows":[["crs","942100","disabled","x"],["crs","942110","disabled","y"]]}`},
		{objectCodec{depth: 8}, `{"a":{"b":{"c":[1,2,{"d":3}]}},"e":null,"f":"x"}`},
		{objectCodec{depth: 2}, `{"entries":{"s":{"deep":{"deeper":1}}},"maintenance":{},"t":"2026-11-21T00:00:00Z"}`},
		{listCodec{id: "id"}, `[{"id":7,"rules":["1"]},{"id":8,"rules":[]}]`},
	}
	for _, c := range cases {
		before, err := c.c.split([]byte(c.blob))
		if err != nil {
			t.Fatalf("%s: %v", c.blob, err)
		}
		out, err := c.c.join([]byte(c.blob), nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		after, _ := c.c.split(out)
		if !reflect.DeepEqual(before, after) {
			t.Errorf("%s: entries changed by a join of nothing:\n%v\n%v", c.blob, before, after)
		}
		// And taking every entry into an empty value gives the same entries.
		fresh, err := c.c.join(emptyOf(c.c, c.blob), before, nil)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := c.c.split(fresh)
		if !reflect.DeepEqual(before, got) {
			t.Errorf("%s: entries taken into an empty value differ:\n%v\n%v", c.blob, before, got)
		}
	}
}

func emptyOf(c entryCodec, blob string) []byte {
	if _, ok := c.(tableCodec); ok {
		var d tableDump
		_ = json.Unmarshal([]byte(blob), &d)
		d.Rows = []json.RawMessage{}
		b, _ := json.Marshal(d)
		return b
	}
	return nil
}
