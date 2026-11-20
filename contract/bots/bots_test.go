package bots_test

import (
	"path/filepath"
	"testing"

	"github.com/deutschland-schild/schild/contract/bots"
	"github.com/deutschland-schild/schild/contract/config"
	"github.com/deutschland-schild/schild/contract/vectors"
)

// The bot-catalogue and bot-match vectors cover the rules; this checks that
// the option defaults equal those of schild.yaml and that the valid
// catalogues of the vectors load with Parse.
func TestDefaultsAndParse(t *testing.T) {
	var b config.Bots
	if bots.DefaultOptions.Ranges != b.RangesOn() || bots.DefaultOptions.FCrDNS != b.FCrDNSOn() {
		t.Fatalf("defaults %+v vs schild.yaml", bots.DefaultOptions)
	}
	files, _ := filepath.Glob("../../contracts/vectors/bot-catalogue/valid/*.json")
	if len(files) == 0 {
		t.Skip("vectors not present")
	}
	for _, f := range files {
		v, err := vectors.Load(f)
		if err != nil {
			t.Fatal(err)
		}
		c, err := bots.Parse([]byte(v.InputRaw))
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if len(c.Bots) == 0 || c.Version == "" {
			t.Fatalf("%s: empty", f)
		}
	}
}
