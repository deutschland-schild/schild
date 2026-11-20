package jsonx

import (
	"errors"
	"strings"
	"testing"
)

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"duplicate key":       `{"a":1,"a":2}`,
		"nested duplicate":    `{"a":{"b":1,"b":1}}`,
		"trailing data":       `{"a":1} {}`,
		"invalid utf8":        "{\"a\":\"\xff\"}",
		"lone high":           `{"a":"\ud800"}`,
		"lone low":            `{"a":"\udc00x"}`,
		"high then text":      `{"a":"\ud800abcdef"}`,
		"nan":                 `{"a":NaN}`,
		"huge number":         `{"a":1e400}`,
		"not json":            `{a:1}`,
		"bom":                 "\xef\xbb\xbf{}",
		"too deep":            strings.Repeat("[", MaxDepth+1) + strings.Repeat("]", MaxDepth+1),
		"empty":               ``,
		"truncated":           `{"a":`,
		"single quote":        `{'a':1}`,
		"comment":             `{"a":1 /* x */}`,
		"trailing comma":      `{"a":1,}`,
		"control char in str": "{\"a\":\"\x01\"}",
	}
	for name, in := range cases {
		if _, err := Parse([]byte(in)); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: want ErrMalformed, got %v", name, err)
		}
	}
}

func TestParseAccepts(t *testing.T) {
	for _, in := range []string{
		`{"a":"\ud83d\ude00"}`,
		`{"a":[1,2.5,-3e2,true,null,"x"]}`,
		strings.Repeat("[", MaxDepth) + strings.Repeat("]", MaxDepth),
		`  {"a" : 1 }  `,
	} {
		if _, err := Parse([]byte(in)); err != nil {
			t.Errorf("%s: %v", in, err)
		}
	}
}

func TestNormalizeAndDecode(t *testing.T) {
	v, err := Parse([]byte(`{"n":1.0,"m":1e3,"f":0.25}`))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		N int     `json:"n"`
		M int     `json:"m"`
		F float64 `json:"f"`
	}
	if err := Decode(v, &out); err != nil {
		t.Fatal(err)
	}
	if out.N != 1 || out.M != 1000 || out.F != 0.25 {
		t.Fatalf("got %+v", out)
	}
	v, _ = Parse([]byte(`{"n":1,"x":2}`))
	if err := Decode(v, &out); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestParseObject(t *testing.T) {
	if _, err := ParseObject([]byte(`[1]`)); err == nil {
		t.Fatal("array accepted as object")
	}
}
