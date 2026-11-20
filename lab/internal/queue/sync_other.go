//go:build !unix

package queue

import "os"

func osSync(f *os.File) error { return f.Sync() }
