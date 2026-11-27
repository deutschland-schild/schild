//go:debug multipathtcp=0

package caddymod

// The tests listen as schild does (cmd/schild/main.go, multipath_test.go
// there): without Multipath TCP. A kernel that has it, as on many Linux
// distributions, refuses the program of firstTakesAll on such a socket
// (EOPNOTSUPP), and Go listens with it unless told otherwise.
