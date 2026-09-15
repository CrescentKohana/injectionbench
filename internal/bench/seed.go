package bench

import (
	"fmt"
	"hash/fnv"
)

// TrialSeed deterministically derives a per-trial seed from base, attackID and trial: the same
// triple always yields the same seed, and different triples very rarely collide.
func TrialSeed(base int64, attackID string, trial int) int64 {
	h := fnv.New64a()
	_, _ = fmt.Fprintf(h, "%d\x00%s\x00%d", base, attackID, trial)
	return int64(h.Sum64()) //nolint:gosec // G115: reinterpreting a hash as a seed; sign carries no meaning
}

// Canary returns "IB-" followed by 16 upper-case hex digits derived deterministically from
// trialSeed via a fixed finalizer, so canaries don't visibly mirror the seed's bit pattern.
func Canary(trialSeed int64) string {
	return fmt.Sprintf("IB-%016X", splitmix64(uint64(trialSeed))) //nolint:gosec // G115: bit pattern reinterpretation, not a bounds-sensitive value
}

func splitmix64(x uint64) uint64 {
	x += 0x9E3779B97F4A7C15
	x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9
	x = (x ^ (x >> 27)) * 0x94D049BB133111EB
	return x ^ (x >> 31)
}
