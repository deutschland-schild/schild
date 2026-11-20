package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/deutschland-schild/schild/contract/jsonx"
)

// YAMLToJSON converts one YAML 1.2 document into JSON with strict rules:
// exactly one document, string keys only, no duplicate keys, no anchors or
// aliases, no merge keys, finite numbers only. Timestamps stay strings.
func YAMLToJSON(b []byte) ([]byte, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("config: empty document")
		}
		return nil, fmt.Errorf("config: yaml: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("config: more than one YAML document")
	}
	v, err := nodeValue(&doc, 0)
	if err != nil {
		return nil, err
	}
	return jsonx.Marshal(v)
}

func nodeValue(n *yaml.Node, depth int) (any, error) {
	if depth > jsonx.MaxDepth {
		return nil, errors.New("config: nesting too deep")
	}
	if n.Anchor != "" {
		return nil, fmt.Errorf("config: line %d: anchors are not allowed", n.Line)
	}
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) != 1 {
			return nil, errors.New("config: empty document")
		}
		return nodeValue(n.Content[0], depth)
	case yaml.AliasNode:
		return nil, fmt.Errorf("config: line %d: aliases are not allowed", n.Line)
	case yaml.MappingNode:
		m := map[string]any{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if k.Kind != yaml.ScalarNode || k.ShortTag() != "!!str" {
				return nil, fmt.Errorf("config: line %d: keys must be strings", k.Line)
			}
			if k.Value == "<<" {
				return nil, fmt.Errorf("config: line %d: merge keys are not allowed", k.Line)
			}
			if _, dup := m[k.Value]; dup {
				return nil, fmt.Errorf("config: line %d: duplicate key %q", k.Line, k.Value)
			}
			x, err := nodeValue(v, depth+1)
			if err != nil {
				return nil, err
			}
			m[k.Value] = x
		}
		return m, nil
	case yaml.SequenceNode:
		a := make([]any, 0, len(n.Content))
		for _, c := range n.Content {
			x, err := nodeValue(c, depth+1)
			if err != nil {
				return nil, err
			}
			a = append(a, x)
		}
		return a, nil
	case yaml.ScalarNode:
		switch n.ShortTag() {
		case "!!str", "!!timestamp", "!!binary":
			return n.Value, nil
		case "!!null":
			return nil, nil
		case "!!bool":
			// Plain true/false resolve here; an explicit !!bool tag may carry
			// any text, and "yes", "on" or "1" must not silently become false.
			switch n.Value {
			case "true", "True", "TRUE":
				return true, nil
			case "false", "False", "FALSE":
				return false, nil
			}
			return nil, fmt.Errorf("config: line %d: bad boolean %q (use true or false)", n.Line, n.Value)
		case "!!int":
			s := strings.ReplaceAll(n.Value, "_", "")
			i, err := strconv.ParseInt(s, 0, 64)
			if err != nil {
				return nil, fmt.Errorf("config: line %d: bad integer %q", n.Line, n.Value)
			}
			return i, nil
		case "!!float":
			f, err := strconv.ParseFloat(n.Value, 64)
			if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
				return nil, fmt.Errorf("config: line %d: bad number %q", n.Line, n.Value)
			}
			return f, nil
		}
		return nil, fmt.Errorf("config: line %d: unsupported tag %s", n.Line, n.ShortTag())
	}
	return nil, fmt.Errorf("config: line %d: unsupported node", n.Line)
}
