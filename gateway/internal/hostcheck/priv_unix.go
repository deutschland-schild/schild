//go:build unix

package hostcheck

import "syscall"

// unprivileged starts a command as nobody (uid/gid 65534) without
// supplementary groups. Needs CAP_SETUID and CAP_SETGID (root has them;
// the shipped units keep them in the bounding set for this drop only).
func unprivileged() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: UnprivilegedUID, Gid: UnprivilegedUID, Groups: []uint32{}}}
}
