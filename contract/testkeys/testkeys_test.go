//go:build !release

package testkeys

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/deutschland-schild/schild/contract/keys"
)

func TestKeyNamesMatch(t *testing.T) {
	if len(All()) != len(keys.TestKeyNames) {
		t.Fatal("testkeys.meta and keys.TestKeyNames differ")
	}
	for i, k := range All() {
		if k.Name != keys.TestKeyNames[i] {
			t.Fatalf("order differs at %d", i)
		}
		if !keys.IsTestKey("x", Trusted(k.Name).Public) {
			t.Fatalf("%s not recognised as test key", k.Name)
		}
	}
}

// The committed contracts/testkeys/keys.json must equal the derivation.
func TestKeysFileInSync(t *testing.T) {
	b, err := os.ReadFile("../../contracts/testkeys/keys.json")
	if os.IsNotExist(err) {
		t.Skip("contracts/ not present")
	}
	if err != nil {
		t.Fatal(err)
	}
	var a, c any
	if err := json.Unmarshal(b, &a); err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(JSON(), &c)
	ab, _ := json.Marshal(a)
	cb, _ := json.Marshal(c)
	if !bytes.Equal(ab, cb) {
		t.Fatal("contracts/testkeys/keys.json out of sync: run make contracts-vectors")
	}
}
