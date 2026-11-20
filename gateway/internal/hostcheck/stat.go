package hostcheck

import (
	"bufio"
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// fileFacts are the stat fields the logs checks use (area logs, D38).
type fileFacts struct {
	Alloc    int64 // bytes allocated (st_blocks * 512)
	UID, GID uint32
	Dev      uint64
	HasOwner bool
}

// factsInfo is implemented by FileInfos that carry their own facts
// (FixtureEnv); real stat results are read through sysFacts.
type factsInfo interface{ statFacts() fileFacts }

func factsOf(fi fs.FileInfo) fileFacts {
	if f, ok := fi.(factsInfo); ok {
		return f.statFacts()
	}
	return sysFacts(fi)
}

// FSStat is the size of a file system and its mount point.
type FSStat struct {
	Mount        string
	Total, Avail int64
}

// FSEnv is implemented by envs that can read file system sizes (statfs).
// Checks work without it (no fs_percent then).
type FSEnv interface {
	StatFS(path string) (FSStat, error)
}

func statFS(env Env, path string) (FSStat, bool) {
	fe, ok := env.(FSEnv)
	if !ok {
		return FSStat{}, false
	}
	s, err := fe.StatFS(path)
	if err != nil || s.Total <= 0 {
		return FSStat{}, false
	}
	return s, true
}

// ---------------------------------------------------------------- fixture

// statOverride replaces stat fields of one fixture path. A fixture tree
// cannot hold a 5 GiB log or files owned by root, so the file "stat" in the
// fixture directory lists overrides, one path per line:
//
//	/var/log/big.log size=5368709120 mtime=2026-10-20T00:00:00Z
//	/etc/logrotate.d/app mode=0664 uid=1000 gid=4
//
// Without an override a fixture file is owned by root (uid and gid 0) and
// has the size it has on disk.
type statOverride struct {
	size     *int64
	uid, gid *uint32
	mode     *fs.FileMode
	mtime    *time.Time
}

type fixtureInfo struct {
	fs.FileInfo
	o statOverride
}

func (f fixtureInfo) Size() int64 {
	if f.o.size != nil {
		return *f.o.size
	}
	return f.FileInfo.Size()
}

func (f fixtureInfo) Mode() fs.FileMode {
	if f.o.mode != nil {
		return f.FileInfo.Mode().Type() | *f.o.mode
	}
	return f.FileInfo.Mode()
}

func (f fixtureInfo) ModTime() time.Time {
	if f.o.mtime != nil {
		return *f.o.mtime
	}
	return f.FileInfo.ModTime()
}

func (f fixtureInfo) statFacts() fileFacts {
	ff := sysFacts(f.FileInfo)
	ff.UID, ff.GID, ff.HasOwner = 0, 0, true
	if f.o.size != nil {
		ff.Alloc = *f.o.size
	}
	if f.o.uid != nil {
		ff.UID = *f.o.uid
	}
	if f.o.gid != nil {
		ff.GID = *f.o.gid
	}
	return ff
}

func (f *FixtureEnv) overrides() map[string]statOverride {
	f.statOnce.Do(func() {
		f.statOver = map[string]statOverride{}
		b, err := os.ReadFile(filepath.Join(f.Dir, "stat"))
		if err != nil {
			return
		}
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			fl := strings.Fields(sc.Text())
			if len(fl) < 2 || strings.HasPrefix(fl[0], "#") {
				continue
			}
			var o statOverride
			for _, kv := range fl[1:] {
				k, v, _ := strings.Cut(kv, "=")
				switch k {
				case "size":
					if n, err := strconv.ParseInt(v, 10, 64); err == nil {
						o.size = &n
					}
				case "uid", "gid":
					if n, err := strconv.ParseUint(v, 10, 32); err == nil {
						u := uint32(n)
						if k == "uid" {
							o.uid = &u
						} else {
							o.gid = &u
						}
					}
				case "mode":
					if n, err := strconv.ParseUint(v, 8, 32); err == nil {
						m := fs.FileMode(n) & fs.ModePerm
						o.mode = &m
					}
				case "mtime":
					if t, err := time.Parse(time.RFC3339, v); err == nil {
						o.mtime = &t
					}
				}
			}
			f.statOver[fl[0]] = o
		}
	})
	return f.statOver
}

// StatFS answers from the file "statfs" in the fixture directory: lines
// "<mount> <total bytes> <available bytes>"; the longest mount that
// contains path wins.
func (f *FixtureEnv) StatFS(path string) (FSStat, error) {
	b, err := os.ReadFile(filepath.Join(f.Dir, "statfs"))
	if err != nil {
		return FSStat{}, errors.New("hostcheck: no statfs in fixture")
	}
	var best FSStat
	for _, l := range strings.Split(string(b), "\n") {
		fl := strings.Fields(l)
		if len(fl) != 3 {
			continue
		}
		m := fl[0]
		if !(path == m || m == "/" || strings.HasPrefix(path, strings.TrimSuffix(m, "/")+"/")) || len(m) < len(best.Mount) {
			continue
		}
		t, err1 := strconv.ParseInt(fl[1], 10, 64)
		a, err2 := strconv.ParseInt(fl[2], 10, 64)
		if err1 == nil && err2 == nil {
			best = FSStat{Mount: m, Total: t, Avail: a}
		}
	}
	if best.Mount == "" {
		return FSStat{}, errors.New("hostcheck: no file system in fixture")
	}
	return best, nil
}
