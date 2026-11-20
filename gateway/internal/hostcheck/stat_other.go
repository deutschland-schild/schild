//go:build !unix

package hostcheck

import (
	"errors"
	"io/fs"
	"os"
)

func sysFacts(fi fs.FileInfo) fileFacts { return fileFacts{Alloc: fi.Size()} }

// openRegular opens path when it is a regular file (schild check runs on
// Linux; this keeps the package building elsewhere).
func openRegular(path string) (*os.File, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, &fs.PathError{Op: "open", Path: path, Err: errNotRegular}
	}
	return os.Open(path)
}

func openDir(path string) (*os.File, error) { return os.Open(path) }

// StatFS is not supported outside unix (schild check runs on Linux).
func (OSEnv) StatFS(string) (FSStat, error) {
	return FSStat{}, errors.New("hostcheck: statfs not supported")
}
