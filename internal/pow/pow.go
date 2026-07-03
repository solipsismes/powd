// Package pow implements powd's Hashcash-style proof of work.
//
// The contract, which the JavaScript solver must match byte for byte:
// a solution solves a challenge token at difficulty d when
//
//	SHA256( token + "." + solution )
//
// has at least d leading zero bits. The hash input includes the complete
// token — MAC and all — so work is bound to one server-issued challenge
// and cannot be precomputed or shared across challenges.
//
// The server accepts any byte string as a solution; the reference client
// happens to use decimal counters. Verification is one SHA-256.
package pow

import (
	"crypto/sha256"
	"math/bits"
	"strconv"
)

// Check reports whether solution solves token at the given difficulty.
// A difficulty of 0 or less is trivially satisfied; the configuration
// layer enforces a sane range.
func Check(token, solution string, difficulty int) bool {
	sum := sha256.Sum256([]byte(token + "." + solution))
	return leadingZeroBits(sum[:]) >= difficulty
}

// Solve brute-forces the smallest decimal-counter solution for token.
// It exists for tests, benchmarks and diagnostics — the server never
// solves, it only checks. Expected work is 2^difficulty hashes.
func Solve(token string, difficulty int) string {
	for i := 0; ; i++ {
		s := strconv.Itoa(i)
		if Check(token, s, difficulty) {
			return s
		}
	}
}

// leadingZeroBits counts the leading zero bits of a digest.
func leadingZeroBits(sum []byte) int {
	n := 0
	for _, b := range sum {
		if b == 0 {
			n += 8
			continue
		}
		return n + bits.LeadingZeros8(b)
	}
	return n
}
