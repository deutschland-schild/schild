package apispec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/deutschland-schild/schild/contract/config"
)

// AgentDoc is the agent API document the gateway serves (D61).
const AgentDoc = "gateway-agent.openapi.yaml"

// Bundle turns the API document name in dir (contracts/api) into one
// self-contained JSON document: every $ref into another file
// (client-dashboard.openapi.yaml, ../common.schema.json) is copied into
// components and points there, so an agent can read the document on its own.
// The output is deterministic.
func Bundle(dir, name string) ([]byte, error) {
	b := &bundler{dir: dir, root: name, files: map[string]any{}, names: map[string]string{}}
	root, err := b.load(name)
	if err != nil {
		return nil, err
	}
	doc := root.(map[string]any)
	b.comps, _ = doc["components"].(map[string]any)
	if b.comps == nil {
		b.comps = map[string]any{}
		doc["components"] = b.comps
	}
	if err := b.rewrite(doc, name); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

type bundler struct {
	dir   string
	root  string
	files map[string]any
	comps map[string]any
	// names maps file#pointer to the local $ref it was copied to.
	names map[string]string
}

func (b *bundler) load(name string) (any, error) {
	if d, ok := b.files[name]; ok {
		return d, nil
	}
	raw, err := os.ReadFile(filepath.Join(b.dir, filepath.FromSlash(name)))
	if err != nil {
		return nil, err
	}
	if strings.HasSuffix(name, ".yaml") {
		if raw, err = config.YAMLToJSON(raw); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var d any
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	b.files[name] = d
	return d, nil
}

// rewrite walks v, which comes from file, and points every $ref at the
// bundle: refs of the root document stay, all others are copied.
func (b *bundler) rewrite(v any, file string) error {
	switch x := v.(type) {
	case map[string]any:
		if ref, ok := x["$ref"].(string); ok {
			local, err := b.resolve(ref, file)
			if err != nil {
				return err
			}
			x["$ref"] = local
		}
		for _, k := range sortedKeys(x) {
			if k == "$ref" {
				continue
			}
			if err := b.rewrite(x[k], file); err != nil {
				return err
			}
		}
	case []any:
		for _, e := range x {
			if err := b.rewrite(e, file); err != nil {
				return err
			}
		}
	}
	return nil
}

func (b *bundler) resolve(ref, file string) (string, error) {
	target, ptr, _ := strings.Cut(ref, "#")
	if target == "" {
		if file == b.root {
			return ref, nil
		}
		target = file
	} else {
		target = path.Clean(path.Join(path.Dir(file), target))
	}
	key := target + "#" + ptr
	if local, ok := b.names[key]; ok {
		return local, nil
	}
	src, err := b.load(target)
	if err != nil {
		return "", err
	}
	node, err := lookup(src, ptr)
	if err != nil {
		return "", fmt.Errorf("%s: %w", key, err)
	}
	kind, name := "schemas", path.Base(ptr)
	if parts := strings.Split(strings.TrimPrefix(ptr, "/"), "/"); len(parts) == 3 && parts[0] == "components" {
		kind = parts[1]
	}
	name = strings.ToUpper(name[:1]) + name[1:]
	section, _ := b.comps[kind].(map[string]any)
	if section == nil {
		section = map[string]any{}
		b.comps[kind] = section
	}
	copied := clone(node)
	if old, taken := section[name]; taken && !reflect.DeepEqual(old, copied) {
		stem := strings.TrimSuffix(strings.TrimSuffix(path.Base(target), ".openapi.yaml"), ".schema.json")
		prefix := ""
		for _, p := range strings.Split(stem, "-") {
			prefix += strings.ToUpper(p[:1]) + p[1:]
		}
		name = prefix + name
		if _, again := section[name]; again {
			return "", fmt.Errorf("%s: %s is taken twice", key, name)
		}
	}
	local := "#/components/" + kind + "/" + name
	b.names[key] = local
	section[name] = copied
	return local, b.rewrite(copied, target)
}

func lookup(doc any, ptr string) (any, error) {
	cur := doc
	for _, p := range strings.Split(strings.TrimPrefix(ptr, "/"), "/") {
		p = strings.ReplaceAll(strings.ReplaceAll(p, "~1", "/"), "~0", "~")
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("no %s", ptr)
		}
		if cur, ok = m[p]; !ok {
			return nil, fmt.Errorf("no %s", ptr)
		}
	}
	return cur, nil
}

func clone(v any) any {
	switch x := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(x))
		for k, e := range x {
			m[k] = clone(e)
		}
		return m
	case []any:
		s := make([]any, len(x))
		for i, e := range x {
			s[i] = clone(e)
		}
		return s
	}
	return v
}

func sortedKeys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
