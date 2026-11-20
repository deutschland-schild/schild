//go:build release

package keys

// Release is true only in builds with -tags release. Release builds refuse
// test keys and the test profile (E5).
const Release = true
