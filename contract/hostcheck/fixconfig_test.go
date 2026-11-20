package hostcheck

import (
	"testing"

	"github.com/deutschland-schild/schild/contract"
)

// v0.5 (D38): every template rendered with in-range variables is known, and
// the content key is allowed only inside fix_config.
func TestFixTemplates(t *testing.T) {
	vars := map[string]string{"slug": "caddy-access", "file": "/var/log/caddy/access.log", "max_size_mb": "200", "max_files": "5",
		"max_use_mb": "1024", "keep_free_mb": "2048", "rotate": "14"}
	for id, ts := range FixTemplates {
		for _, tp := range ts {
			f := RenderFix(tp, vars)
			if !FixConfigKnown(id, f.Path, f.Content) {
				t.Errorf("%s: own rendering not known: %+v", id, f)
			}
			if FixConfigKnown(id, f.Path, f.Content+"#") {
				t.Errorf("%s: extra content accepted", id)
			}
		}
	}
	ok := map[string]any{"findings": []any{map[string]any{"fix_config": map[string]any{"path": "/x", "content": "y"}}}}
	if err := CheckForbidden(ok); err != nil {
		t.Fatal(err)
	}
	bad := map[string]any{"findings": []any{map[string]any{"evidence": map[string]any{"content": "y"}}}}
	if contract.CodeOf(CheckForbidden(bad)) != contract.CodeForbiddenField {
		t.Fatal("content outside fix_config not caught")
	}
}
