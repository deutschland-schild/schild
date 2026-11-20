//go:build !release

package main

import (
	"github.com/deutschland-schild/schild/contract/keys"
	"github.com/deutschland-schild/schild/contract/testkeys"
)

func testTrust(names []string) (*keys.TrustStore, error) { return testkeys.TrustStore(names...), nil }
