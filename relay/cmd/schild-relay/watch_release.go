//go:build release

package main

import (
	"errors"

	"github.com/deutschland-schild/schild/contract/keys"
)

func testTrust([]string) (*keys.TrustStore, error) {
	return nil, errors.New("test keys are not available in release builds")
}
