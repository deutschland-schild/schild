//go:debug multipathtcp=0

package app

// The tests listen as schild does (cmd/schild/main.go, multipath_test.go
// there): without Multipath TCP. With it a reload of the Caddyfile loses
// connections (caddymod/socket.go).
