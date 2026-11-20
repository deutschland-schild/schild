// Package sources generates deterministic pools of IPv4 and IPv6 source
// addresses from the test lab's internal ranges, for botnet simulation. The
// pool is a function of the seed only, so a scenario replays identically.
//
// The addresses live inside the "inet" network ranges of conventions §6
// (10.66.20.0/22 and fd66::14:0:0:0/80 for profile t1); they never route out.
package sources

import (
	"fmt"
	"math/rand"
)

// Pool returns n deterministic source addresses, mixing IPv4 and IPv6. The mix
// is roughly 3:1 IPv4:IPv6. base4 is the first two octets of the /22 base
// (e.g. [10,66,20]) and must be the inet range of the active profile.
func Pool(seed int64, n int, v4base [3]byte, v6prefix string) []string {
	rng := rand.New(rand.NewSource(seed))
	out := make([]string, 0, n)
	seen := map[string]bool{}
	for len(out) < n {
		var ip string
		if rng.Intn(4) == 0 {
			// IPv6 inside the /80: fd66:...:xxxx:xxxx:xxxx
			ip = fmt.Sprintf("%s:%x:%x:%x", v6prefix, rng.Intn(0x10000), rng.Intn(0x10000), rng.Intn(0x10000))
		} else {
			// IPv4 inside the /22: base.(0..3).(1..254)
			third := int(v4base[2]) + rng.Intn(4)
			host := 1 + rng.Intn(254)
			ip = fmt.Sprintf("%d.%d.%d.%d", v4base[0], v4base[1], third, host)
		}
		if seen[ip] {
			continue
		}
		seen[ip] = true
		out = append(out, ip)
	}
	return out
}

// T1Inet is the inet IPv4 base for profile t1 (10.66.20.0/22).
var T1Inet = [3]byte{10, 66, 20}

// T0Inet is the inet IPv4 base for profile t0 (10.66.4.0/22).
var T0Inet = [3]byte{10, 66, 4}

// T1Inet6 is the inet IPv6 prefix for profile t1 (fd66:0:0:14::/80).
const T1Inet6 = "fd66:0:0:14"

// T0Inet6 is the inet IPv6 prefix for profile t0 (fd66:0:0:4::/80).
const T0Inet6 = "fd66:0:0:4"
