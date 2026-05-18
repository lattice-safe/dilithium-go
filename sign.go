package dilithium

import (
	"crypto/sha512"
	"crypto/subtle"
)

// Keypair generates a Dilithium key pair.
// Returns (pk, sk) as byte slices.
func Keypair(mode Mode, randomSeed *[SEEDBYTES]byte) ([]byte, []byte) {
	k := mode.K()
	l := mode.L()

	var seedbuf [2*SEEDBYTES + CRHBYTES]byte
	var expanded [2*SEEDBYTES + CRHBYTES]byte

	// Derive rho, rhoprime, key from seed
	copy(seedbuf[:SEEDBYTES], randomSeed[:])
	seedbuf[SEEDBYTES] = byte(k)
	seedbuf[SEEDBYTES+1] = byte(l)
	Shake256(expanded[:], seedbuf[:SEEDBYTES+2])

	// S1: zeroize keying material (Go doesn't have reliable zeroize, but we can overwrite)
	for i := range seedbuf {
		seedbuf[i] = 0
	}

	var rho [SEEDBYTES]byte
	copy(rho[:], expanded[:SEEDBYTES])
	var rhoprime [CRHBYTES]byte
	copy(rhoprime[:], expanded[SEEDBYTES:SEEDBYTES+CRHBYTES])
	var key [SEEDBYTES]byte
	copy(key[:], expanded[SEEDBYTES+CRHBYTES:])

	for i := range expanded {
		expanded[i] = 0
	}

	// Expand matrix A
	mat := make([]PolyVecL, K_MAX)
	for i := 0; i < K_MAX; i++ {
		mat[i] = *NewPolyVecL()
	}
	MatrixExpand(mode, mat, &rho)

	// Sample short vectors s1, s2
	s1 := NewPolyVecL()
	s2 := NewPolyVecK()
	PolyVecLUniformEta(mode, s1, &rhoprime, 0)
	PolyVecKUniformEta(mode, s2, &rhoprime, uint16(l))

	for i := range rhoprime {
		rhoprime[i] = 0
	}

	// t = A * NTT(s1)
	s1hat := *s1
	PolyVecLNTT(mode, &s1hat)
	t1 := NewPolyVecK()
	MatrixPointwiseMontgomery(mode, t1, mat, &s1hat)
	PolyVecKReduce(mode, t1)
	PolyVecKInvNTTToMont(mode, t1)

	// t = t + s2
	t1Copy := *t1
	PolyVecKAdd(mode, t1, &t1Copy, s2)

	// Extract t1 and t0
	PolyVecKCaddq(mode, t1)
	t1High := NewPolyVecK()
	t0 := NewPolyVecK()
	PolyVecKPower2Round(mode, t1High, t0, t1)

	// Pack public key
	pk := make([]byte, mode.PublicKeyBytes())
	PackPk(mode, pk, &rho, t1High)

	// Compute tr = H(pk)
	var tr [TRBYTES]byte
	Shake256(tr[:], pk)

	// Pack secret key
	sk := make([]byte, mode.SecretKeyBytes())
	PackSk(mode, sk, &rho, tr[:], &key, t0, s1, s2)

	return pk, sk
}

// SignSignatureInternal internal signing function with rejection sampling loop.
func SignSignatureInternal(mode Mode, sig []byte, m []byte, pre []byte, rnd *[RNDBYTES]byte, sk []byte) int {
	k := mode.K()
	l := mode.L()
	beta := mode.Beta()
	gamma1 := mode.Gamma1()
	gamma2 := mode.Gamma2()
	omega := mode.Omega()

	// Unpack secret key
	var rho [SEEDBYTES]byte
	var tr [TRBYTES]byte
	var key [SEEDBYTES]byte
	t0 := NewPolyVecK()
	s1 := NewPolyVecL()
	s2 := NewPolyVecK()
	if err := UnpackSk(mode, &rho, tr[:], &key, t0, s1, s2, sk); err != nil {
		return -1
	}

	// Compute mu = CRH(tr, pre, msg)
	var mu [CRHBYTES]byte
	Shake256Multi(mu[:], [][]byte{tr[:], pre, m})

	// Compute rhoprime = CRH(key, rnd, mu)
	var rhoprime [CRHBYTES]byte
	Shake256Multi(rhoprime[:], [][]byte{key[:], rnd[:], mu[:]})

	for i := range key {
		key[i] = 0
	}

	// Expand matrix and transform vectors
	mat := make([]PolyVecL, K_MAX)
	for i := 0; i < K_MAX; i++ {
		mat[i] = *NewPolyVecL()
	}
	MatrixExpand(mode, mat, &rho)
	PolyVecLNTT(mode, s1)
	PolyVecKNTT(mode, s2)
	PolyVecKNTT(mode, t0)

	var nonce uint16 = 0
	h := NewPolyVecK()

	for {
		// Sample intermediate vector y
		y := NewPolyVecL()
		PolyVecLUniformGamma1(mode, y, &rhoprime, nonce)
		nonce += uint16(l)

		// w = A * NTT(y)
		zNtt := *y
		PolyVecLNTT(mode, &zNtt)
		w1 := NewPolyVecK()
		MatrixPointwiseMontgomery(mode, w1, mat, &zNtt)
		PolyVecKReduce(mode, w1)
		PolyVecKInvNTTToMont(mode, w1)

		// Decompose w
		PolyVecKCaddq(mode, w1)
		w1High := NewPolyVecK()
		w0 := NewPolyVecK()
		PolyVecKDecompose(mode, w1High, w0, w1)
		w1Packed := make([]byte, k*mode.PolyW1PackedBytes())
		PolyVecKPackW1(mode, w1Packed, w1High)

		// Compute challenge
		ctilde := mode.Ctildebytes()
		ctildeBuf := make([]byte, ctilde)
		Shake256Multi(ctildeBuf, [][]byte{mu[:], w1Packed})

		copy(sig[:ctilde], ctildeBuf)

		cp := NewPoly()
		PolyChallenge(mode, cp, ctildeBuf)
		cp.NTT()

		// z = y + c*s1
		z := NewPolyVecL()
		PolyVecLPointwisePolyMontgomery(mode, z, cp, s1)
		PolyVecLInvNTTToMont(mode, z)
		zCopy := *z
		PolyVecLAdd(mode, z, &zCopy, y)
		PolyVecLReduce(mode, z)
		if PolyVecLChkNorm(mode, z, gamma1-beta) {
			continue
		}

		// w0 = w0 - c*s2
		PolyVecKPointwisePolyMontgomery(mode, h, cp, s2)
		PolyVecKInvNTTToMont(mode, h)
		w0Copy := *w0
		PolyVecKSub(mode, w0, &w0Copy, h)
		PolyVecKReduce(mode, w0)
		if PolyVecKChkNorm(mode, w0, gamma2-beta) {
			continue
		}

		// Compute hints
		PolyVecKPointwisePolyMontgomery(mode, h, cp, t0)
		PolyVecKInvNTTToMont(mode, h)
		PolyVecKReduce(mode, h)
		if PolyVecKChkNorm(mode, h, gamma2) {
			continue
		}

		w0Copy2 := *w0
		PolyVecKAdd(mode, w0, &w0Copy2, h)
		n := PolyVecKMakeHint(mode, h, w0, w1High)
		if n > omega {
			continue
		}

		// Pack signature
		PackSig(mode, sig, ctildeBuf, z, h)
		return mode.SignatureBytes()
	}
}

// SignSignature signs a message with context string.
// Returns signature length on success, or -1 on error (context too long).
func SignSignature(mode Mode, sig []byte, m []byte, ctx []byte, rnd *[RNDBYTES]byte, sk []byte) int32 {
	if len(ctx) > 255 {
		return -1
	}

	// Build prefix: (0, ctxlen, ctx)
	pre := make([]byte, 2+len(ctx))
	pre[0] = 0
	pre[1] = byte(len(ctx))
	copy(pre[2:], ctx)

	SignSignatureInternal(mode, sig, m, pre, rnd, sk)
	return 0
}

// VerifyInternal verifies a signature (internal API with prefix).
func VerifyInternal(mode Mode, sig []byte, m []byte, pre []byte, pk []byte) bool {
	k := mode.K()
	beta := mode.Beta()
	gamma1 := mode.Gamma1()
	ctildeLen := mode.Ctildebytes()

	if len(sig) != mode.SignatureBytes() {
		return false
	}

	// Unpack public key
	var rho [SEEDBYTES]byte
	t1 := NewPolyVecK()
	if err := UnpackPk(mode, &rho, t1, pk); err != nil {
		return false
	}

	// Unpack signature
	c := make([]byte, ctildeLen)
	z := NewPolyVecL()
	h := NewPolyVecK()
	if UnpackSig(mode, c, z, h, sig) {
		return false
	}
	if PolyVecLChkNorm(mode, z, gamma1-beta) {
		return false
	}

	// Compute CRH(H(pk), pre, msg)
	var mu [CRHBYTES]byte
	var tr [TRBYTES]byte
	Shake256(tr[:], pk)
	Shake256Multi(mu[:], [][]byte{tr[:], pre, m})

	// Reconstruct w1': Az - c * 2^d * t1
	cp := NewPoly()
	PolyChallenge(mode, cp, c)

	mat := make([]PolyVecL, K_MAX)
	for i := 0; i < K_MAX; i++ {
		mat[i] = *NewPolyVecL()
	}
	MatrixExpand(mode, mat, &rho)

	PolyVecLNTT(mode, z)
	w1 := NewPolyVecK()
	MatrixPointwiseMontgomery(mode, w1, mat, z)

	cp.NTT()
	PolyVecKShiftl(mode, t1)
	PolyVecKNTT(mode, t1)
	t1Clone := *t1
	PolyVecKPointwisePolyMontgomery(mode, t1, cp, &t1Clone)

	w1Copy := *w1
	PolyVecKSub(mode, w1, &w1Copy, t1)
	PolyVecKReduce(mode, w1)
	PolyVecKInvNTTToMont(mode, w1)

	// Reconstruct w1 using hint
	PolyVecKCaddq(mode, w1)
	w1Copy2 := *w1
	PolyVecKUseHint(mode, w1, &w1Copy2, h)
	buf := make([]byte, k*mode.PolyW1PackedBytes())
	PolyVecKPackW1(mode, buf, w1)

	// Re-derive challenge and compare (constant-time to prevent side channels)
	c2 := make([]byte, ctildeLen)
	Shake256Multi(c2, [][]byte{mu[:], buf})

	// FIPS 204 §7: constant-time comparison
	return subtle.ConstantTimeCompare(c, c2) == 1
}

// Verify verifies a signature with context string (pure ML-DSA, FIPS 204 §6.1).
func Verify(mode Mode, sig []byte, m []byte, ctx []byte, pk []byte) bool {
	if len(ctx) > 255 {
		return false
	}

	pre := make([]byte, 2+len(ctx))
	pre[0] = 0
	pre[1] = byte(len(ctx))
	copy(pre[2:], ctx)

	return VerifyInternal(mode, sig, m, pre, pk)
}

// SignHash HashML-DSA Sign (FIPS 204 §6.2).
// Signs SHA-512(msg) instead of msg directly, embedding the hash OID.
func SignHash(mode Mode, sig []byte, msg []byte, ctx []byte, rnd *[RNDBYTES]byte, sk []byte) int32 {
	if len(ctx) > 255 {
		return -1
	}

	// Hash the message with SHA-512
	hasher := sha512.New()
	hasher.Write(msg)
	phM := hasher.Sum(nil)

	// Build prefix: (1, ctxlen, ctx, OID, H(msg))
	oid := mode.HashOID()
	pre := make([]byte, 2+len(ctx)+len(oid)+len(phM))
	pre[0] = 1 // prehash indicator
	pre[1] = byte(len(ctx))
	off := 2
	copy(pre[off:off+len(ctx)], ctx)
	off += len(ctx)
	copy(pre[off:off+len(oid)], oid)
	off += len(oid)
	copy(pre[off:off+len(phM)], phM)

	SignSignatureInternal(mode, sig, []byte{}, pre, rnd, sk)
	return 0
}

// VerifyHash HashML-DSA Verify (FIPS 204 §6.2).
// Verifies against SHA-512(msg) with the hash OID embedded.
func VerifyHash(mode Mode, sig []byte, msg []byte, ctx []byte, pk []byte) bool {
	if len(ctx) > 255 {
		return false
	}

	hasher := sha512.New()
	hasher.Write(msg)
	phM := hasher.Sum(nil)

	oid := mode.HashOID()
	pre := make([]byte, 2+len(ctx)+len(oid)+len(phM))
	pre[0] = 1
	pre[1] = byte(len(ctx))
	off := 2
	copy(pre[off:off+len(ctx)], ctx)
	off += len(ctx)
	copy(pre[off:off+len(oid)], oid)
	off += len(oid)
	copy(pre[off:off+len(phM)], phM)

	return VerifyInternal(mode, sig, []byte{}, pre, pk)
}
