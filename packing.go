package dilithium

import "errors"

// PackPk packs public key: pk = (rho, t1).
func PackPk(mode Mode, pk []byte, rho *[SEEDBYTES]byte, t1 *PolyVecK) {
	copy(pk[:SEEDBYTES], rho[:])
	offset := SEEDBYTES
	for i := 0; i < mode.K(); i++ {
		PolyT1Pack(pk[offset:offset+POLYT1_PACKEDBYTES], &t1.Vec[i])
		offset += POLYT1_PACKEDBYTES
	}
}

// UnpackPk unpacks public key: pk = (rho, t1).
func UnpackPk(mode Mode, rho *[SEEDBYTES]byte, t1 *PolyVecK, pk []byte) error {
	if len(pk) != mode.PublicKeyBytes() {
		return errors.New("invalid public key length")
	}
	copy(rho[:], pk[:SEEDBYTES])
	offset := SEEDBYTES
	for i := 0; i < mode.K(); i++ {
		PolyT1Unpack(&t1.Vec[i], pk[offset:offset+POLYT1_PACKEDBYTES])
		offset += POLYT1_PACKEDBYTES
	}
	return nil
}

// PackSk packs secret key: sk = (rho, key, tr, s1, s2, t0).
func PackSk(mode Mode, sk []byte, rho *[SEEDBYTES]byte, tr []byte, key *[SEEDBYTES]byte, t0 *PolyVecK, s1 *PolyVecL, s2 *PolyVecK) {
	etaPacked := mode.PolyEtaPackedBytes()
	offset := 0

	// rho
	copy(sk[offset:offset+SEEDBYTES], rho[:])
	offset += SEEDBYTES

	// key
	copy(sk[offset:offset+SEEDBYTES], key[:])
	offset += SEEDBYTES

	// tr
	copy(sk[offset:offset+TRBYTES], tr[:TRBYTES])
	offset += TRBYTES

	// s1
	for i := 0; i < mode.L(); i++ {
		PolyEtaPack(mode, sk[offset:offset+etaPacked], &s1.Vec[i])
		offset += etaPacked
	}

	// s2
	for i := 0; i < mode.K(); i++ {
		PolyEtaPack(mode, sk[offset:offset+etaPacked], &s2.Vec[i])
		offset += etaPacked
	}

	// t0
	for i := 0; i < mode.K(); i++ {
		PolyT0Pack(sk[offset:offset+POLYT0_PACKEDBYTES], &t0.Vec[i])
		offset += POLYT0_PACKEDBYTES
	}
}

// UnpackSk unpacks secret key: sk = (rho, key, tr, s1, s2, t0).
func UnpackSk(mode Mode, rho *[SEEDBYTES]byte, tr []byte, key *[SEEDBYTES]byte, t0 *PolyVecK, s1 *PolyVecL, s2 *PolyVecK, sk []byte) error {
	if len(sk) != mode.SecretKeyBytes() {
		return errors.New("invalid secret key length")
	}
	etaPacked := mode.PolyEtaPackedBytes()
	offset := 0

	// rho
	copy(rho[:], sk[offset:offset+SEEDBYTES])
	offset += SEEDBYTES

	// key
	copy(key[:], sk[offset:offset+SEEDBYTES])
	offset += SEEDBYTES

	// tr
	copy(tr[:TRBYTES], sk[offset:offset+TRBYTES])
	offset += TRBYTES

	// s1
	for i := 0; i < mode.L(); i++ {
		PolyEtaUnpack(mode, &s1.Vec[i], sk[offset:offset+etaPacked])
		offset += etaPacked
	}

	// s2
	for i := 0; i < mode.K(); i++ {
		PolyEtaUnpack(mode, &s2.Vec[i], sk[offset:offset+etaPacked])
		offset += etaPacked
	}

	// t0
	for i := 0; i < mode.K(); i++ {
		PolyT0Unpack(&t0.Vec[i], sk[offset:offset+POLYT0_PACKEDBYTES])
		offset += POLYT0_PACKEDBYTES
	}
	return nil
}

// PackSig packs signature: sig = (c̃, z, h).
func PackSig(mode Mode, sig []byte, c []byte, z *PolyVecL, h *PolyVecK) {
	ctilde := mode.Ctildebytes()
	polyzPacked := mode.PolyZPackedBytes()
	omega := mode.Omega()
	k := mode.K()

	// c̃
	copy(sig[:ctilde], c[:ctilde])
	offset := ctilde

	// z
	for i := 0; i < mode.L(); i++ {
		PolyZPack(mode, sig[offset:offset+polyzPacked], &z.Vec[i])
		offset += polyzPacked
	}

	// h (hint encoding)
	hStart := offset
	for i := 0; i < omega+k; i++ {
		sig[hStart+i] = 0
	}

	idx := 0
	for i := 0; i < k; i++ {
		for j := 0; j < N; j++ {
			if h.Vec[i].Coeffs[j] != 0 {
				sig[hStart+idx] = byte(j)
				idx++
			}
		}
		sig[hStart+omega+i] = byte(idx)
	}
}

// UnpackSig unpacks signature: sig = (c̃, z, h).
// Returns true on malformed signature.
func UnpackSig(mode Mode, c []byte, z *PolyVecL, h *PolyVecK, sig []byte) bool {
	if len(sig) != mode.SignatureBytes() {
		return true
	}
	ctilde := mode.Ctildebytes()
	polyzPacked := mode.PolyZPackedBytes()
	omega := mode.Omega()
	k := mode.K()

	// c̃
	copy(c[:ctilde], sig[:ctilde])
	offset := ctilde

	// z
	for i := 0; i < mode.L(); i++ {
		PolyZUnpack(mode, &z.Vec[i], sig[offset:offset+polyzPacked])
		offset += polyzPacked
	}

	// h (hint decoding)
	hStart := offset
	idx := 0
	for i := 0; i < k; i++ {
		for j := 0; j < N; j++ {
			h.Vec[i].Coeffs[j] = 0
		}

		end := int(sig[hStart+omega+i])
		if end < idx || end > omega {
			return true
		}

		for j := idx; j < end; j++ {
			// Coefficients are ordered for strong unforgeability
			if j > idx && sig[hStart+j] <= sig[hStart+j-1] {
				return true
			}
			h.Vec[i].Coeffs[sig[hStart+j]] = 1
		}

		idx = end
	}

	// Extra indices must be zero
	for j := idx; j < omega; j++ {
		if sig[hStart+j] != 0 {
			return true
		}
	}

	return false
}
