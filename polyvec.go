package dilithium

// PolyVecL represents a vector of polynomials of length L (max L=7 for Mode5).
type PolyVecL struct {
	Vec [L_MAX]Poly
}

// NewPolyVecL creates a PolyVecL initialized to zero.
func NewPolyVecL() *PolyVecL {
	return &PolyVecL{}
}

// PolyVecK represents a vector of polynomials of length K (max K=8 for Mode5).
type PolyVecK struct {
	Vec [K_MAX]Poly
}

// NewPolyVecK creates a PolyVecK initialized to zero.
func NewPolyVecK() *PolyVecK {
	return &PolyVecK{}
}

// MatrixExpand expands matrix A from seed rho. Matrix is K x L of polynomials.
func MatrixExpand(mode Mode, mat []PolyVecL, rho *[SEEDBYTES]byte) {
	k := mode.K()
	l := mode.L()
	for i := 0; i < k; i++ {
		for j := 0; j < l; j++ {
			PolyUniform(&mat[i].Vec[j], rho, uint16((i<<8)+j))
		}
	}
}

// MatrixPointwiseMontgomery performs matrix-vector multiplication: t = A * v (in NTT domain).
func MatrixPointwiseMontgomery(mode Mode, t *PolyVecK, mat []PolyVecL, v *PolyVecL) {
	k := mode.K()
	for i := 0; i < k; i++ {
		PolyVecLPointwiseAccMontgomery(mode, &t.Vec[i], &mat[i], v)
	}
}

// PolyVecLUniformEta samples short vector with eta-bounded coefficients.
func PolyVecLUniformEta(mode Mode, v *PolyVecL, seed *[CRHBYTES]byte, nonce uint16) {
	l := mode.L()
	for i := 0; i < l; i++ {
		PolyUniformEta(mode, &v.Vec[i], seed, nonce+uint16(i))
	}
}

// PolyVecLUniformGamma1 samples masking vector with gamma1-bounded coefficients.
func PolyVecLUniformGamma1(mode Mode, v *PolyVecL, seed *[CRHBYTES]byte, nonce uint16) {
	l := mode.L()
	for i := 0; i < l; i++ {
		PolyUniformGamma1(mode, &v.Vec[i], seed, nonce+uint16(i))
	}
}

// PolyVecLReduce reduces all coefficients of polynomials in vector.
func PolyVecLReduce(mode Mode, v *PolyVecL) {
	l := mode.L()
	for i := 0; i < l; i++ {
		v.Vec[i].Reduce()
	}
}

// PolyVecLAdd adds vectors of polynomials: w = u + v.
func PolyVecLAdd(mode Mode, w *PolyVecL, u *PolyVecL, v *PolyVecL) {
	l := mode.L()
	for i := 0; i < l; i++ {
		PolyAdd(&w.Vec[i], &u.Vec[i], &v.Vec[i])
	}
}

// PolyVecLNTT performs forward NTT of all polynomials in vector.
func PolyVecLNTT(mode Mode, v *PolyVecL) {
	l := mode.L()
	for i := 0; i < l; i++ {
		v.Vec[i].NTT()
	}
}

// PolyVecLInvNTTToMont performs inverse NTT of all polynomials in vector.
func PolyVecLInvNTTToMont(mode Mode, v *PolyVecL) {
	l := mode.L()
	for i := 0; i < l; i++ {
		v.Vec[i].InvNTTToMont()
	}
}

// PolyVecLPointwisePolyMontgomery pointwise multiplies all polynomials in vector by scalar polynomial.
func PolyVecLPointwisePolyMontgomery(mode Mode, r *PolyVecL, a *Poly, v *PolyVecL) {
	l := mode.L()
	for i := 0; i < l; i++ {
		PolyPointwiseMontgomery(&r.Vec[i], a, &v.Vec[i])
	}
}

// PolyVecLPointwiseAccMontgomery pointwise multiplies two vectors and accumulates.
func PolyVecLPointwiseAccMontgomery(mode Mode, w *Poly, u *PolyVecL, v *PolyVecL) {
	l := mode.L()
	var t Poly
	PolyPointwiseMontgomery(w, &u.Vec[0], &v.Vec[0])
	for i := 1; i < l; i++ {
		PolyPointwiseMontgomery(&t, &u.Vec[i], &v.Vec[i])
		wCopy := *w
		PolyAdd(w, &wCopy, &t)
	}
}

// PolyVecLChkNorm checks infinity norm of polynomials in vector.
// Returns true if any polynomial has norm >= bound.
func PolyVecLChkNorm(mode Mode, v *PolyVecL, bound int32) bool {
	l := mode.L()
	for i := 0; i < l; i++ {
		if v.Vec[i].ChkNorm(bound) {
			return true
		}
	}
	return false
}

// PolyVecKUniformEta samples short vector with eta-bounded coefficients.
func PolyVecKUniformEta(mode Mode, v *PolyVecK, seed *[CRHBYTES]byte, nonce uint16) {
	k := mode.K()
	for i := 0; i < k; i++ {
		PolyUniformEta(mode, &v.Vec[i], seed, nonce+uint16(i))
	}
}

// PolyVecKReduce reduces all coefficients.
func PolyVecKReduce(mode Mode, v *PolyVecK) {
	k := mode.K()
	for i := 0; i < k; i++ {
		v.Vec[i].Reduce()
	}
}

// PolyVecKCaddq adds Q if negative.
func PolyVecKCaddq(mode Mode, v *PolyVecK) {
	k := mode.K()
	for i := 0; i < k; i++ {
		v.Vec[i].Caddq()
	}
}

// PolyVecKAdd adds vectors: w = u + v.
func PolyVecKAdd(mode Mode, w *PolyVecK, u *PolyVecK, v *PolyVecK) {
	k := mode.K()
	for i := 0; i < k; i++ {
		PolyAdd(&w.Vec[i], &u.Vec[i], &v.Vec[i])
	}
}

// PolyVecKSub subtracts vectors: w = u - v.
func PolyVecKSub(mode Mode, w *PolyVecK, u *PolyVecK, v *PolyVecK) {
	k := mode.K()
	for i := 0; i < k; i++ {
		PolySub(&w.Vec[i], &u.Vec[i], &v.Vec[i])
	}
}

// PolyVecKShiftl shifts left by D.
func PolyVecKShiftl(mode Mode, v *PolyVecK) {
	k := mode.K()
	for i := 0; i < k; i++ {
		v.Vec[i].Shiftl()
	}
}

// PolyVecKNTT performs forward NTT.
func PolyVecKNTT(mode Mode, v *PolyVecK) {
	k := mode.K()
	for i := 0; i < k; i++ {
		v.Vec[i].NTT()
	}
}

// PolyVecKInvNTTToMont performs inverse NTT.
func PolyVecKInvNTTToMont(mode Mode, v *PolyVecK) {
	k := mode.K()
	for i := 0; i < k; i++ {
		v.Vec[i].InvNTTToMont()
	}
}

// PolyVecKPointwisePolyMontgomery pointwise multiplies vector by scalar polynomial.
func PolyVecKPointwisePolyMontgomery(mode Mode, r *PolyVecK, a *Poly, v *PolyVecK) {
	k := mode.K()
	for i := 0; i < k; i++ {
		PolyPointwiseMontgomery(&r.Vec[i], a, &v.Vec[i])
	}
}

// PolyVecKPower2Round performs power-of-2 rounding of all polynomials.
func PolyVecKPower2Round(mode Mode, v1 *PolyVecK, v0 *PolyVecK, v *PolyVecK) {
	k := mode.K()
	for i := 0; i < k; i++ {
		PolyPower2Round(&v1.Vec[i], &v0.Vec[i], &v.Vec[i])
	}
}

// PolyVecKDecompose decomposes all polynomials.
func PolyVecKDecompose(mode Mode, v1 *PolyVecK, v0 *PolyVecK, v *PolyVecK) {
	k := mode.K()
	for i := 0; i < k; i++ {
		PolyDecompose(mode, &v1.Vec[i], &v0.Vec[i], &v.Vec[i])
	}
}

// PolyVecKMakeHint makes hint for all polynomials. Returns number of ones.
func PolyVecKMakeHint(mode Mode, h *PolyVecK, v0 *PolyVecK, v1 *PolyVecK) int {
	k := mode.K()
	s := 0
	for i := 0; i < k; i++ {
		s += PolyMakeHint(mode, &h.Vec[i], &v0.Vec[i], &v1.Vec[i])
	}
	return s
}

// PolyVecKUseHint uses hint for all polynomials.
func PolyVecKUseHint(mode Mode, w *PolyVecK, v *PolyVecK, h *PolyVecK) {
	k := mode.K()
	for i := 0; i < k; i++ {
		PolyUseHint(mode, &w.Vec[i], &v.Vec[i], &h.Vec[i])
	}
}

// PolyVecKPackW1 packs w1 polynomials.
func PolyVecKPackW1(mode Mode, r []byte, w1 *PolyVecK) {
	k := mode.K()
	packed := mode.PolyW1PackedBytes()
	for i := 0; i < k; i++ {
		PolyW1Pack(mode, r[i*packed:(i+1)*packed], &w1.Vec[i])
	}
}

// PolyVecKChkNorm checks infinity norm of polynomials in vector.
func PolyVecKChkNorm(mode Mode, v *PolyVecK, bound int32) bool {
	k := mode.K()
	for i := 0; i < k; i++ {
		if v.Vec[i].ChkNorm(bound) {
			return true
		}
	}
	return false
}
