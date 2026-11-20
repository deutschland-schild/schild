//go:build unix

package queue

import (
	"os"
	"syscall"
)

// osSync is fsync(2). On Linux it is what os.File.Sync does; on macOS it
// does not flush the drive's write cache (os.File.Sync uses F_FULLFSYNC).
func osSync(f *os.File) error { return syscall.Fsync(int(f.Fd())) }
