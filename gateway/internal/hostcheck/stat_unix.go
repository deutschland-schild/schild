//go:build unix

package hostcheck

import (
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// openRegular opens path (following symbolic links) for reading only when it
// is a regular file. The stat before the open keeps FIFOs and device nodes
// from being opened at all; O_NONBLOCK and O_NOCTTY cover a swap between
// stat and open (a FIFO then opens without waiting for a writer, a terminal
// does not become the controlling one), and the fstat after it must show
// the same regular file.
func openRegular(path string) (*os.File, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, &fs.PathError{Op: "open", Path: path, Err: errNotRegular}
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, err
	}
	if fst, err := f.Stat(); err != nil || !fst.Mode().IsRegular() || !os.SameFile(st, fst) {
		f.Close()
		return nil, &fs.PathError{Op: "open", Path: path, Err: errNotRegular}
	}
	return f, nil
}

// openDir opens path only when it is a directory: with O_DIRECTORY the
// kernel refuses anything else before opening it, so a FIFO cannot block.
func openDir(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
}

// sysFacts reads the stat fields the logs checks use from a real stat
// result: the allocated size from st_blocks (sparse files such as lastlog
// count what they occupy), owner, group and device.
func sysFacts(fi fs.FileInfo) fileFacts {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fileFacts{Alloc: fi.Size()}
	}
	return fileFacts{Alloc: int64(st.Blocks) * 512, UID: st.Uid, GID: st.Gid, Dev: uint64(st.Dev), HasOwner: true}
}

// StatFS reads the size of the file system holding path (statfs, read
// only) and finds its mount point by comparing the device of the parent
// directories (stat only; /proc/self/mountinfo is not read).
func (OSEnv) StatFS(path string) (FSStat, error) {
	var s syscall.Statfs_t
	if err := syscall.Statfs(path, &s); err != nil {
		return FSStat{}, err
	}
	out := FSStat{Total: int64(s.Blocks) * int64(s.Bsize), Avail: int64(s.Bavail) * int64(s.Bsize), Mount: "/"}
	st, err := os.Stat(path)
	if err != nil {
		return out, nil
	}
	dev := sysFacts(st).Dev
	p := filepath.Clean(path)
	for p != "/" {
		parent := filepath.Dir(p)
		pst, err := os.Stat(parent)
		if err != nil || sysFacts(pst).Dev != dev {
			out.Mount = p
			return out, nil
		}
		p = parent
	}
	return out, nil
}
