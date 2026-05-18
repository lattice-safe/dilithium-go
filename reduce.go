package dilithium

// MontgomeryReduce performs Montgomery reduction.
// For finite field element a with -2^{31}*Q <= a <= Q*2^{31},
// compute r ≡ a * 2^{-32} (mod Q) such that -Q < r < Q.
func montgomeryReduce(a int64) int32 {
	t := int32(a) * int32(QINV)
	return int32((a - int64(t)*int64(Q)) >> 32)
}

// Reduce32 performs Barrett-like reduction.
// For finite field element a with a <= 2^{31} - 2^{22} - 1,
// compute r ≡ a (mod Q) such that -6283008 <= r <= 6283008.
func reduce32(a int32) int32 {
	t := (a + (1 << 22)) >> 23
	return a - t*Q
}

// Caddq conditionally adds Q.
// Add Q if input coefficient is negative.
func caddq(a int32) int32 {
	return a + ((a >> 31) & Q)
}


