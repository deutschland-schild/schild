package config

import "testing"

func TestYAMLToJSONBooleans(t *testing.T) {
	for in, want := range map[string]string{
		"a: true":             `{"a":true}`,
		"a: False":            `{"a":false}`,
		"a: !!bool TRUE":      `{"a":true}`,
		"a: !!bool false":     `{"a":false}`,
		"a: yes":              `{"a":"yes"}`, // YAML 1.2: a string, the schema decides
		"a: !!str true":       `{"a":"true"}`,
		"a: [true, false]":    `{"a":[true,false]}`,
		"a: {b: !!bool true}": `{"a":{"b":true}}`,
	} {
		j, err := YAMLToJSON([]byte(in))
		if err != nil || string(j) != want {
			t.Errorf("%q: %s %v, want %s", in, j, err, want)
		}
	}
	// An explicit !!bool tag on anything else used to turn into false.
	for _, in := range []string{"a: !!bool yes", "a: !!bool on", "a: !!bool 1", "a: !!bool ''"} {
		if j, err := YAMLToJSON([]byte(in)); err == nil {
			t.Errorf("%q accepted as %s", in, j)
		}
	}
}
