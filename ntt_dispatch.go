package dilithium

import "golang.org/x/sys/cpu"

var hasAVX2 = cpu.X86.HasAVX2

// NTT computes the forward Number Theoretic Transform in-place.
// It dispatches to AVX2 assembly if supported by the CPU, otherwise falls back to scalar.
func NTT(a *[256]int32) {
	if hasAVX2 {
		nttAVX2(a)
	} else {
		nttScalar(a)
	}
}

// InvNTT computes the inverse Number Theoretic Transform in-place.
// It dispatches to AVX2 assembly if supported by the CPU, otherwise falls back to scalar.
func InvNTT(a *[256]int32) {
	if hasAVX2 {
		invnttAVX2(a)
	} else {
		invNTTScalar(a)
	}
}
