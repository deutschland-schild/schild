//go:build !linux

package diskbudget

import "golang.org/x/sys/unix"

// statfs on the BSDs and macOS: f_bsize is the fundamental block size (the
// unit of f_blocks and f_bavail; there is no f_frsize).
func statfs(p string) (total, avail int64, err error) {
	var st unix.Statfs_t
	if err := unix.Statfs(p, &st); err != nil {
		return 0, 0, err
	}
	return int64(st.Blocks) * int64(st.Bsize), int64(st.Bavail) * int64(st.Bsize), nil //nolint:unconvert // field types differ per OS
}
