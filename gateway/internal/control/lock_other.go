//go:build !unix

package control

import "os"

// lockFile outside unix only creates the file: schild runs on Linux, the
// lock is advisory there.
func lockFile(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	return func() { _ = f.Close() }, nil
}
