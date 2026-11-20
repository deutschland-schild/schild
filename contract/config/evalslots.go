package config

// WAF evaluation slots (waf.max_concurrent_evals; initiator decision
// 2026-10-29, D31 amendment and MVP-19 note). Of n slots, expensive
// evaluations (the cost classes of MVP-19 fix round 2) use at most
// ExpensiveEvalSlots(n); the other ReservedEvalSlots(n) are never used by an
// expensive evaluation, so cheap ordinary requests (typical page views,
// small forms) keep slots of their own during a flood of expensive
// requests. Cheap evaluations may use every slot.
//
//	expensive = min(max(1, floor(n/2)), n - min(2, n-1))
//	reserved  = n - expensive
//
// reserved is at least min(2, n-1): 1 on 2 slots, 2 on 3 and 4 slots, half
// from 4 slots on. n below MinEvalSlots counts as MinEvalSlots (the schema
// minimum; the derived default GOMAXPROCS is raised to it). No override
// (environment variable, test setting) may raise the expensive slots above
// ExpensiveEvalSlots.

// MinEvalSlots is the smallest number of evaluation slots.
const MinEvalSlots = 2

// ExpensiveEvalSlots returns how many of n slots expensive evaluations may
// use at once.
func ExpensiveEvalSlots(n int) int {
	n = max(n, MinEvalSlots)
	return min(max(1, n/2), n-min(2, n-1))
}

// NetEvalShare returns how many expensive evaluations one IPv6 /48 may hold at
// once, of maxHeavy expensive slots: half, rounded up (D43). Whoever owns a
// /48 owns 65536 /64 networks, so a share per client does not bound it; half
// leaves the other half to everybody else. With one expensive slot there is
// nothing to divide.
func NetEvalShare(maxHeavy int) int {
	return max(1, (maxHeavy+1)/2)
}

// ReservedEvalSlots returns how many of n slots expensive evaluations never
// use.
func ReservedEvalSlots(n int) int {
	return max(n, MinEvalSlots) - ExpensiveEvalSlots(n)
}
