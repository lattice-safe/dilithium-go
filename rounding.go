package dilithium

// Power2round performs power-of-2 rounding.
// For finite field element a, compute a0, a1 such that
// a mod^+ Q = a1*2^D + a0 with -2^{D-1} < a0 <= 2^{D-1}.
// Assumes a to be standard representative.
// Returns (a1, a0).
func power2round(a int32) (int32, int32) {
	a1 := (a + (1 << (D - 1)) - 1) >> D
	a0 := a - (a1 << D)
	return a1, a0
}

// Decompose performs high/low bit decomposition.
// For finite field element a, compute high and low bits a0, a1 such that
// a mod^+ Q = a1*ALPHA + a0 with -ALPHA/2 < a0 <= ALPHA/2 except
// if a1 = (Q-1)/ALPHA where we set a1 = 0 and
// -ALPHA/2 <= a0 = a mod^+ Q - Q < 0. Assumes a to be standard representative.
// Returns (a1, a0).
func decompose(mode Mode, a int32) (int32, int32) {
	gamma2 := mode.Gamma2()
	a1 := (a + 127) >> 7

	if gamma2 == (Q-1)/32 {
		a1 = (a1*1025 + (1 << 21)) >> 22
		a1 &= 15
	} else {
		// gamma2 == (Q-1)/88
		a1 = (a1*11275 + (1 << 23)) >> 24
		a1 ^= ((43 - a1) >> 31) & a1
	}

	a0 := a - a1*2*gamma2
	a0 -= (((Q - 1) / 2 - a0) >> 31) & Q
	return a1, a0
}

// MakeHint computes hint bit indicating whether the low bits of the input element
// overflow into the high bits.
// Returns true if overflow.
func makeHint(mode Mode, a0 int32, a1 int32) bool {
	gamma2 := mode.Gamma2()
	return a0 > gamma2 || a0 < -gamma2 || (a0 == -gamma2 && a1 != 0)
}

// UseHint corrects high bits according to hint.
// Returns corrected high bits.
func useHint(mode Mode, a int32, hint bool) int32 {
	gamma2 := mode.Gamma2()
	a1, a0 := decompose(mode, a)

	if !hint {
		return a1
	}

	if gamma2 == (Q-1)/32 {
		if a0 > 0 {
			return (a1 + 1) & 15
		} else {
			return (a1 - 1) & 15
		}
	} else {
		// gamma2 == (Q-1)/88
		if a0 > 0 {
			if a1 == 43 {
				return 0
			} else {
				return a1 + 1
			}
		} else if a1 == 0 {
			return 43
		} else {
			return a1 - 1
		}
	}
}
