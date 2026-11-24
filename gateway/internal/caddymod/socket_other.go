//go:build !linux

package caddymod

import (
	"errors"
	"net"
)

func firstTakesAll(*net.TCPListener) error { return errors.ErrUnsupported }
