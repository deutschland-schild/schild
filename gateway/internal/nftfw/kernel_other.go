//go:build !linux

package nftfw

import "errors"

// Kernel is nftables, which exists on Linux only.
type Kernel struct{}

var errNotLinux = errors.New("the firewall of schild needs Linux (nftables)")

func (Kernel) Ensure() error           { return errNotLinux }
func (Kernel) Replace([]Element) error { return errNotLinux }
func (Kernel) Held() ([]Held, error)   { return nil, errNotLinux }
func (Kernel) Remove() error           { return errNotLinux }
