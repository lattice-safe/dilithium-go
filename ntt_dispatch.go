package dilithium

import "golang.org/x/sys/cpu"

var hasAVX2 = cpu.X86.HasAVX2

// NTT computes the forward Number Theoretic Transform in-place.
// It dispatches to AVX2 assembly if supported by the CPU, otherwise falls back to scalar.
func NTT(a *[256]int32) {
	if hasAVX2 {
		nttAVX2_8(a, &zetas)

		// Hybrid approach: Finish len=4, 2, 1 in scalar Go
		k := 31 // 1 + 2 + 4 + 8 + 16 = 31 zetas used
		len := 4
		for len > 0 {
			start := 0
			for start < 256 {
				k++
				zeta := zetas[k]
				for j := start; j < start+len; j++ {
					t := montgomeryReduce(int64(zeta) * int64(a[j+len]))
					a[j+len] = a[j] - t
					a[j] += t
				}
				start += 2 * len
			}
			len >>= 1
		}
	} else {
		nttScalar(a)
	}
}

// InvNTT computes the inverse Number Theoretic Transform in-place.
// It dispatches to AVX2 assembly if supported by the CPU, otherwise falls back to scalar.
func InvNTT(a *[256]int32) {
	if hasAVX2 {
		// Hybrid approach for InvNTT goes from len=1 to len=256.
		// AVX2 handles len >= 4 usually in Rust, but we can just use scalar for now until fully implemented.
		// Since we haven't implemented invnttAVX2_8 yet in the generator, fallback to scalar.
		invNTTScalar(a)
	} else {
		invNTTScalar(a)
	}
}
