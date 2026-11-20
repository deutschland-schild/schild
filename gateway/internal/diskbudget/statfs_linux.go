//go:build linux

package diskbudget

import "golang.org/x/sys/unix"

func statfs(p string) (total, avail int64, err error) {
	var st unix.Statfs_t
	if err := unix.Statfs(p, &st); err != nil {
		return 0, 0, err
	}
	frsize := int64(st.Frsize) //nolint:unconvert // field types differ per architecture
	if frsize <= 0 {
		frsize = int64(st.Bsize) //nolint:unconvert // field types differ per architecture
	}
	return int64(st.Blocks) * frsize, int64(st.Bavail) * frsize, nil //nolint:unconvert // field types differ per architecture
}
