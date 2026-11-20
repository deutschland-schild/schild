//go:build !unix

package hostcheck

import "syscall"

// unprivileged: no uid switch outside unix; OSEnv refuses nothing else
// here because schild check only runs on Linux.
func unprivileged() *syscall.SysProcAttr { return &syscall.SysProcAttr{} }
