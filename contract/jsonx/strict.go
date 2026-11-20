// Package jsonx parses JSON strictly and identically to the Python
// cross-check: valid UTF-8 only, no duplicate keys, no lone surrogate
// escapes, no trailing data, bounded depth, only finite numbers.
package jsonx

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"strconv"
	"unicode/utf8"
)

// ErrMalformed is wrapped by every parse error.
var ErrMalformed = errors.New("malformed json")

// MaxDepth is the maximum nesting of arrays and objects.
const MaxDepth = 32

// Parse decodes data into a generic value (map[string]any, []any, string,
// json.Number, bool, nil).
func Parse(data []byte) (any, error) {
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("%w: invalid utf-8", ErrMalformed)
	}
	if err := checkSurrogates(data); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := parseValue(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: trailing data", ErrMalformed)
	}
	return v, nil
}

// ParseObject is Parse but requires a JSON object at the top level.
func ParseObject(data []byte) (map[string]any, error) {
	v, err := Parse(data)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: top level is not an object", ErrMalformed)
	}
	return m, nil
}

func parseValue(dec *json.Decoder, depth int) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	switch t := tok.(type) {
	case json.Delim:
		if depth+1 > MaxDepth {
			return nil, fmt.Errorf("%w: nesting deeper than %d", ErrMalformed, MaxDepth)
		}
		switch t {
		case '{':
			m := map[string]any{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
				}
				k, ok := kt.(string)
				if !ok {
					return nil, fmt.Errorf("%w: object key is not a string", ErrMalformed)
				}
				if _, dup := m[k]; dup {
					return nil, fmt.Errorf("%w: duplicate key %q", ErrMalformed, k)
				}
				v, err := parseValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				m[k] = v
			}
			if _, err := dec.Token(); err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
			}
			return m, nil
		case '[':
			a := []any{}
			for dec.More() {
				v, err := parseValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			if _, err := dec.Token(); err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
			}
			return a, nil
		}
		return nil, fmt.Errorf("%w: unexpected delimiter %v", ErrMalformed, t)
	case json.Number:
		f, err := strconv.ParseFloat(string(t), 64)
		if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
			return nil, fmt.Errorf("%w: number out of range: %s", ErrMalformed, t)
		}
		return t, nil
	default:
		return t, nil
	}
}

// checkSurrogates rejects \uD800-\uDFFF escapes that do not form a valid pair.
func checkSurrogates(data []byte) error {
	inStr := false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if !inStr {
			if c == '"' {
				inStr = true
			}
			continue
		}
		switch c {
		case '"':
			inStr = false
		case '\\':
			if i+1 >= len(data) {
				return nil // let the decoder report it
			}
			if data[i+1] != 'u' {
				i++
				continue
			}
			r, ok := hex4(data, i+2)
			if !ok {
				return nil
			}
			switch {
			case r >= 0xD800 && r <= 0xDBFF:
				if i+11 < len(data) && data[i+6] == '\\' && data[i+7] == 'u' {
					if lo, ok := hex4(data, i+8); ok && lo >= 0xDC00 && lo <= 0xDFFF {
						i += 11
						continue
					}
				}
				return fmt.Errorf("%w: lone surrogate escape", ErrMalformed)
			case r >= 0xDC00 && r <= 0xDFFF:
				return fmt.Errorf("%w: lone surrogate escape", ErrMalformed)
			}
			i += 5
		}
	}
	return nil
}

func hex4(data []byte, at int) (rune, bool) {
	if at+4 > len(data) {
		return 0, false
	}
	n, err := strconv.ParseUint(string(data[at:at+4]), 16, 32)
	if err != nil {
		return 0, false
	}
	return rune(n), true
}

// Normalize rewrites integral numbers written as 1.0 or 1e3 to plain
// integer literals so that typed decoding agrees with JSON Schema, where
// 1.0 is an integer.
func Normalize(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			t[k] = Normalize(x)
		}
		return t
	case []any:
		for i, x := range t {
			t[i] = Normalize(x)
		}
		return t
	case json.Number:
		s := string(t)
		if bytes.ContainsAny([]byte(s), ".eE") {
			r, ok := new(big.Rat).SetString(s)
			if ok && r.IsInt() && r.Num().IsInt64() {
				return json.Number(r.Num().String())
			}
		}
		return t
	}
	return v
}

// Decode converts a generic value into out, rejecting unknown fields.
func Decode(v any, out any) error {
	b, err := json.Marshal(Normalize(v))
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	return nil
}

// Marshal encodes compact JSON without HTML escaping.
func Marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
