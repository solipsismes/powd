package pow

import (
	"strconv"
	"testing"
)

// fixedToken/fixedSolution pin the exact hash-input contract
// SHA256(token + "." + solution). The pair was computed independently
// (Python hashlib); its digest is 0009bf86… = exactly 12 leading zero
// bits. If this test breaks, the wire contract changed and the
// JavaScript solver no longer agrees with the server.
const (
	fixedToken    = "powd1.1720000120.12.00000000000000000000000000000000.deadbeef"
	fixedSolution = "13213"
)

func TestFixedVector(t *testing.T) {
	for d := 1; d <= 12; d++ {
		if !Check(fixedToken, fixedSolution, d) {
			t.Errorf("Check(fixed vector, difficulty %d) = false, want true", d)
		}
	}
	// The digest has exactly 12 leading zero bits.
	if Check(fixedToken, fixedSolution, 13) {
		t.Error("Check(fixed vector, difficulty 13) = true, want false")
	}
}

func TestCheckRejects(t *testing.T) {
	// Deterministic non-solutions for the fixed token.
	if Check(fixedToken, "0", 32) {
		t.Error(`Check(fixedToken, "0", 32) = true`)
	}
	// Any perturbation of a valid pair must fail at the same difficulty.
	if Check(fixedToken+"x", fixedSolution, 12) {
		t.Error("perturbed token still checks")
	}
	if Check(fixedToken, fixedSolution+"0", 12) {
		t.Error("perturbed solution still checks")
	}
}

func TestZeroDifficultyIsTrivial(t *testing.T) {
	if !Check("anything", "at all", 0) {
		t.Error("difficulty 0 should always check")
	}
}

func TestSolve(t *testing.T) {
	token := "powd1.1720000120.10.ffffffffffffffffffffffffffffffff.cafe"
	for d := 1; d <= 10; d++ {
		sol := Solve(token, d)
		if !Check(token, sol, d) {
			t.Fatalf("Solve produced a non-solution at difficulty %d: %q", d, sol)
		}
		// Solve returns the smallest counter, so its predecessor fails.
		if n, _ := strconv.Atoi(sol); n > 0 {
			if Check(token, strconv.Itoa(n-1), d) {
				t.Errorf("difficulty %d: %d checks but Solve returned %d", d, n-1, n)
			}
		}
	}
}

func TestDifficultyIsMonotonic(t *testing.T) {
	token := "monotonic-test-token"
	sol := Solve(token, 10)
	for d := 0; d <= 10; d++ {
		if !Check(token, sol, d) {
			t.Errorf("solution for difficulty 10 fails at lower difficulty %d", d)
		}
	}
}

func TestLeadingZeroBits(t *testing.T) {
	tests := []struct {
		sum  []byte
		want int
	}{
		{[]byte{}, 0},
		{[]byte{0x80}, 0},
		{[]byte{0xff, 0x00}, 0},
		{[]byte{0x40}, 1},
		{[]byte{0x01}, 7},
		{[]byte{0x00, 0xff}, 8},
		{[]byte{0x00, 0x80}, 8},
		{[]byte{0x00, 0x09}, 12}, // the fixed vector's prefix
		{[]byte{0x00, 0x01}, 15},
		{[]byte{0x00, 0x00}, 16},
		{[]byte{0x00, 0x00, 0x20}, 18},
	}
	for _, tt := range tests {
		if got := leadingZeroBits(tt.sum); got != tt.want {
			t.Errorf("leadingZeroBits(% x) = %d, want %d", tt.sum, got, tt.want)
		}
	}
}

// BenchmarkCheck documents the server-side verification cost: one SHA-256
// over ~80 bytes. Only the client pays for solving.
func BenchmarkCheck(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Check(fixedToken, fixedSolution, 12)
	}
}
