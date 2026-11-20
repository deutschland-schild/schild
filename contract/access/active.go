package access

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// ActiveFile is the file schild writes into <storage>/access/ whenever a
// protection changes (D56). `schild front` reads it when schild refuses the
// connection: while any protection is in force it answers 503 instead of
// failing open to the app. nginx and Caddy in front check for ActiveMarker,
// which exists exactly while ActiveFile lists a protection.
const (
	ActiveDir    = "access"
	ActiveFile   = "active.json"
	ActiveMarker = "active"
)

// Active is the content of ActiveFile.
type Active struct {
	Version     int            `json:"version"`
	Protections []ActiveRecord `json:"protections"`
}

// ActiveRecord is one protection in ActiveFile. No password, no addresses.
type ActiveRecord struct {
	Website string `json:"website"`
	Scope   string `json:"scope"`
}

// InForce reports whether a protection is on. A protection has no end
// (D58); it holds until it is removed.
func (a Active) InForce() bool { return len(a.Protections) > 0 }

// ReadActive reads ActiveFile below dir (the storage path). The caller
// counts an error as a protection in force: the front must not fail open on
// doubt. A missing file is an error too (D71): schild writes the file at
// every start, so a missing one means the reader cannot see schild's
// storage, not that nothing is locked.
func ReadActive(dir string) (Active, error) {
	b, err := os.ReadFile(filepath.Join(dir, ActiveDir, ActiveFile))
	if err != nil {
		return Active{}, err
	}
	var a Active
	if err := json.Unmarshal(b, &a); err != nil {
		return Active{}, err
	}
	return a, nil
}

// WriteActive writes a atomically below dir and creates or removes
// ActiveMarker to match (the marker is written first and removed last, so
// it never claims less than the file).
func WriteActive(dir string, a Active) error {
	d := filepath.Join(dir, ActiveDir)
	if err := os.MkdirAll(d, 0o750); err != nil {
		return err
	}
	a.Version = 1
	if a.Protections == nil {
		a.Protections = []ActiveRecord{}
	}
	b, err := json.Marshal(a)
	if err != nil {
		return err
	}
	marker := filepath.Join(d, ActiveMarker)
	inForce := a.InForce()
	if inForce {
		if err := os.WriteFile(marker, []byte("1\n"), 0o640); err != nil {
			return err
		}
	}
	tmp, err := os.CreateTemp(d, ".active-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), filepath.Join(d, ActiveFile)); err != nil {
		return err
	}
	if !inForce {
		if err := os.Remove(marker); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}
