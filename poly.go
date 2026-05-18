package dilithium

// Stream block sizes matching SHAKE rates.
const (
	STREAM128_BLOCKBYTES = 168 // SHAKE128_RATE
	STREAM256_BLOCKBYTES = 136 // SHAKE256_RATE
)

// Poly represents a polynomial in Z_Q[X]/(X^N + 1).
type Poly struct {
	Coeffs [N]int32
}

// NewPoly creates a zero polynomial.
func NewPoly() *Poly {
	return &Poly{}
}

// Reduce performs in-place reduction of all coefficients to [-6283008, 6283008].
func (p *Poly) Reduce() {
	for i := 0; i < N; i++ {
		p.Coeffs[i] = reduce32(p.Coeffs[i])
	}
}

// Caddq adds Q if coefficient is negative.
func (p *Poly) Caddq() {
	for i := 0; i < N; i++ {
		p.Coeffs[i] = caddq(p.Coeffs[i])
	}
}

// PolyAdd adds two polynomials: c = a + b. No modular reduction.
func PolyAdd(c, a, b *Poly) {
	for i := 0; i < N; i++ {
		c.Coeffs[i] = a.Coeffs[i] + b.Coeffs[i]
	}
}

// PolySub subtracts polynomials: c = a - b. No modular reduction.
func PolySub(c, a, b *Poly) {
	for i := 0; i < N; i++ {
		c.Coeffs[i] = a.Coeffs[i] - b.Coeffs[i]
	}
}

// Shiftl multiplies polynomial by 2^D without modular reduction.
func (p *Poly) Shiftl() {
	for i := 0; i < N; i++ {
		p.Coeffs[i] <<= D
	}
}

// NTT performs in-place forward NTT.
func (p *Poly) NTT() {
	NTT(&p.Coeffs)
}

// InvNTTToMont performs in-place inverse NTT with Montgomery factor.
func (p *Poly) InvNTTToMont() {
	InvNTT(&p.Coeffs)
}

// PolyPointwiseMontgomery performs pointwise multiplication in NTT domain with Montgomery reduction.
func PolyPointwiseMontgomery(c, a, b *Poly) {
	for i := 0; i < N; i++ {
		c.Coeffs[i] = montgomeryReduce(int64(a.Coeffs[i]) * int64(b.Coeffs[i]))
	}
}

// PolyPower2Round performs power-of-2 rounding.
func PolyPower2Round(a1, a0, a *Poly) {
	for i := 0; i < N; i++ {
		a1.Coeffs[i], a0.Coeffs[i] = power2round(a.Coeffs[i])
	}
}

// PolyDecompose decomposes into high and low bits.
func PolyDecompose(mode Mode, a1, a0, a *Poly) {
	for i := 0; i < N; i++ {
		a1.Coeffs[i], a0.Coeffs[i] = decompose(mode, a.Coeffs[i])
	}
}

// PolyMakeHint computes hint polynomial. Returns number of 1 bits.
func PolyMakeHint(mode Mode, h, a0, a1 *Poly) int {
	s := 0
	for i := 0; i < N; i++ {
		if makeHint(mode, a0.Coeffs[i], a1.Coeffs[i]) {
			h.Coeffs[i] = 1
			s++
		} else {
			h.Coeffs[i] = 0
		}
	}
	return s
}

// PolyUseHint uses hint polynomial to correct high bits.
func PolyUseHint(mode Mode, b, a, h *Poly) {
	for i := 0; i < N; i++ {
		b.Coeffs[i] = useHint(mode, a.Coeffs[i], h.Coeffs[i] != 0)
	}
}

// ChkNorm checks infinity norm against bound B.
// Returns true if norm >= B (i.e., check fails).
func (p *Poly) ChkNorm(bound int32) bool {
	if bound > (Q-1)/8 {
		return true
	}
	for i := 0; i < N; i++ {
		t := p.Coeffs[i] >> 31
		t = p.Coeffs[i] - (t & (2 * p.Coeffs[i]))
		if t >= bound {
			return true
		}
	}
	return false
}

// RejUniform performs rejection sampling: sample uniform coefficients in [0, Q-1].
// Returns number of coefficients written.
func RejUniform(a []int32, buf []byte) int {
	length := len(a)
	buflen := len(buf)
	ctr := 0
	pos := 0

	for ctr < length && pos+3 <= buflen {
		t := uint32(buf[pos])
		t |= uint32(buf[pos+1]) << 8
		t |= uint32(buf[pos+2]) << 16
		t &= 0x7FFFFF
		pos += 3

		if t < uint32(Q) {
			a[ctr] = int32(t)
			ctr++
		}
	}
	return ctr
}

// Uniform samples polynomial with uniformly random coefficients in [0, Q-1]
// via rejection sampling on output of SHAKE128.
func PolyUniform(a *Poly, seed *[SEEDBYTES]byte, nonce uint16) {
	const nblocks = (768 + STREAM128_BLOCKBYTES - 1) / STREAM128_BLOCKBYTES

	stream := NewStream128(seed, nonce)
	buf := make([]byte, nblocks*STREAM128_BLOCKBYTES+2)
	stream.Squeeze(buf[:nblocks*STREAM128_BLOCKBYTES])

	ctr := RejUniform(a.Coeffs[:N], buf[:nblocks*STREAM128_BLOCKBYTES])

	tmp := make([]byte, STREAM128_BLOCKBYTES)
	for ctr < N {
		stream.Squeeze(tmp)
		ctr += RejUniform(a.Coeffs[ctr:N], tmp)
	}
}

// RejEta performs rejection sampling for eta-bounded coefficients in [-ETA, ETA].
func RejEta(mode Mode, a []int32, buf []byte) int {
	eta := mode.Eta()
	length := len(a)
	buflen := len(buf)
	ctr := 0
	pos := 0

	for ctr < length && pos < buflen {
		t0 := uint32(buf[pos] & 0x0F)
		t1 := uint32(buf[pos] >> 4)
		pos++

		if eta == 2 {
			if t0 < 15 {
				t0 = t0 - ((t0 * 205) >> 10 << 2) - ((t0 * 205) >> 10)
				a[ctr] = 2 - int32(t0%5)
				ctr++
			}
			if t1 < 15 && ctr < length {
				t1 = t1 - ((t1 * 205) >> 10 << 2) - ((t1 * 205) >> 10)
				a[ctr] = 2 - int32(t1%5)
				ctr++
			}
		} else { // eta == 4
			if t0 < 9 {
				a[ctr] = 4 - int32(t0)
				ctr++
			}
			if t1 < 9 && ctr < length {
				a[ctr] = 4 - int32(t1)
				ctr++
			}
		}
	}
	return ctr
}

// PolyUniformEta samples polynomial with coefficients in [-ETA, ETA] via SHAKE256.
func PolyUniformEta(mode Mode, a *Poly, seed *[CRHBYTES]byte, nonce uint16) {
	var nblocks int
	if mode.Eta() == 2 {
		nblocks = (136 + STREAM256_BLOCKBYTES - 1) / STREAM256_BLOCKBYTES
	} else {
		nblocks = (227 + STREAM256_BLOCKBYTES - 1) / STREAM256_BLOCKBYTES
	}

	stream := NewStream256(seed, nonce)
	buf := make([]byte, nblocks*STREAM256_BLOCKBYTES)
	stream.Squeeze(buf)

	ctr := RejEta(mode, a.Coeffs[:N], buf)
	tmp := make([]byte, STREAM256_BLOCKBYTES)
	for ctr < N {
		stream.Squeeze(tmp)
		ctr += RejEta(mode, a.Coeffs[ctr:N], tmp)
	}
}

// PolyUniformGamma1 samples polynomial with coefficients in [-(GAMMA1-1), GAMMA1]
// by unpacking SHAKE256 stream output.
func PolyUniformGamma1(mode Mode, a *Poly, seed *[CRHBYTES]byte, nonce uint16) {
	polyzPacked := mode.PolyZPackedBytes()
	nblocks := (polyzPacked + STREAM256_BLOCKBYTES - 1) / STREAM256_BLOCKBYTES

	stream := NewStream256(seed, nonce)
	buf := make([]byte, nblocks*STREAM256_BLOCKBYTES)
	stream.Squeeze(buf)

	PolyZUnpack(mode, a, buf)
}

// PolyChallenge samples challenge polynomial with TAU nonzero coefficients in {-1, 1}
// using SHAKE256(seed).
func PolyChallenge(mode Mode, c *Poly, seed []byte) {
	tau := mode.Tau()

	state := NewShake256State()
	state.Absorb(seed)
	reader := state.Finalize()

	var buf [8]byte
	reader.Squeeze(buf[:])
	signs := uint64(buf[0]) | uint64(buf[1])<<8 | uint64(buf[2])<<16 | uint64(buf[3])<<24 |
		uint64(buf[4])<<32 | uint64(buf[5])<<40 | uint64(buf[6])<<48 | uint64(buf[7])<<56

	for i := 0; i < N; i++ {
		c.Coeffs[i] = 0
	}

	var b [1]byte
	for i := N - tau; i < N; i++ {
		for {
			reader.Squeeze(b[:])
			if int(b[0]) <= i {
				break
			}
		}
		j := int(b[0])
		c.Coeffs[i] = c.Coeffs[j]
		c.Coeffs[j] = 1 - 2*int32(signs&1)
		signs >>= 1
	}
}

// PolyEtaPack packs polynomial with eta-bounded coefficients.
func PolyEtaPack(mode Mode, r []byte, a *Poly) {
	eta := mode.Eta()
	if eta == 2 {
		for i := 0; i < N/8; i++ {
			var t [8]byte
			for j := 0; j < 8; j++ {
				t[j] = byte(eta - a.Coeffs[8*i+j])
			}
			r[3*i+0] = t[0] | (t[1] << 3) | (t[2] << 6)
			r[3*i+1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7)
			r[3*i+2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5)
		}
	} else {
		for i := 0; i < N/2; i++ {
			t0 := byte(eta - a.Coeffs[2*i+0])
			t1 := byte(eta - a.Coeffs[2*i+1])
			r[i] = t0 | (t1 << 4)
		}
	}
}

// PolyEtaUnpack unpacks polynomial with eta-bounded coefficients.
func PolyEtaUnpack(mode Mode, r *Poly, a []byte) {
	eta := mode.Eta()
	if eta == 2 {
		for i := 0; i < N/8; i++ {
			r.Coeffs[8*i+0] = int32(a[3*i+0] & 7)
			r.Coeffs[8*i+1] = int32((a[3*i+0] >> 3) & 7)
			r.Coeffs[8*i+2] = int32(((a[3*i+0] >> 6) | (a[3*i+1] << 2)) & 7)
			r.Coeffs[8*i+3] = int32((a[3*i+1] >> 1) & 7)
			r.Coeffs[8*i+4] = int32((a[3*i+1] >> 4) & 7)
			r.Coeffs[8*i+5] = int32(((a[3*i+1] >> 7) | (a[3*i+2] << 1)) & 7)
			r.Coeffs[8*i+6] = int32((a[3*i+2] >> 2) & 7)
			r.Coeffs[8*i+7] = int32((a[3*i+2] >> 5) & 7)

			for j := 0; j < 8; j++ {
				r.Coeffs[8*i+j] = eta - r.Coeffs[8*i+j]
			}
		}
	} else {
		for i := 0; i < N/2; i++ {
			r.Coeffs[2*i+0] = int32(a[i] & 0x0F)
			r.Coeffs[2*i+1] = int32(a[i] >> 4)
			r.Coeffs[2*i+0] = eta - r.Coeffs[2*i+0]
			r.Coeffs[2*i+1] = eta - r.Coeffs[2*i+1]
		}
	}
}

// PolyT1Pack packs t1 polynomial (10-bit coefficients).
func PolyT1Pack(r []byte, a *Poly) {
	for i := 0; i < N/4; i++ {
		r[5*i+0] = byte(a.Coeffs[4*i+0])
		r[5*i+1] = byte((a.Coeffs[4*i+0] >> 8) | (a.Coeffs[4*i+1] << 2))
		r[5*i+2] = byte((a.Coeffs[4*i+1] >> 6) | (a.Coeffs[4*i+2] << 4))
		r[5*i+3] = byte((a.Coeffs[4*i+2] >> 4) | (a.Coeffs[4*i+3] << 6))
		r[5*i+4] = byte(a.Coeffs[4*i+3] >> 2)
	}
}

// PolyT1Unpack unpacks t1 polynomial (10-bit coefficients).
func PolyT1Unpack(r *Poly, a []byte) {
	for i := 0; i < N/4; i++ {
		r.Coeffs[4*i+0] = int32((uint32(a[5*i+0]) | (uint32(a[5*i+1]) << 8)) & 0x3FF)
		r.Coeffs[4*i+1] = int32(((uint32(a[5*i+1]) >> 2) | (uint32(a[5*i+2]) << 6)) & 0x3FF)
		r.Coeffs[4*i+2] = int32(((uint32(a[5*i+2]) >> 4) | (uint32(a[5*i+3]) << 4)) & 0x3FF)
		r.Coeffs[4*i+3] = int32((uint32(a[5*i+3]) >> 6) | (uint32(a[5*i+4]) << 2))
	}
}

// PolyT0Pack packs t0 polynomial (13-bit coefficients in ]-2^{D-1}, 2^{D-1}]).
func PolyT0Pack(r []byte, a *Poly) {
	var t [8]int32
	for i := 0; i < N/8; i++ {
		for j := 0; j < 8; j++ {
			t[j] = (1 << (D - 1)) - a.Coeffs[8*i+j]
		}
		r[13*i+0] = byte(t[0])
		r[13*i+1] = byte(t[0] >> 8)
		r[13*i+1] |= byte(t[1] << 5)
		r[13*i+2] = byte(t[1] >> 3)
		r[13*i+3] = byte(t[1] >> 11)
		r[13*i+3] |= byte(t[2] << 2)
		r[13*i+4] = byte(t[2] >> 6)
		r[13*i+4] |= byte(t[3] << 7)
		r[13*i+5] = byte(t[3] >> 1)
		r[13*i+6] = byte(t[3] >> 9)
		r[13*i+6] |= byte(t[4] << 4)
		r[13*i+7] = byte(t[4] >> 4)
		r[13*i+8] = byte(t[4] >> 12)
		r[13*i+8] |= byte(t[5] << 1)
		r[13*i+9] = byte(t[5] >> 7)
		r[13*i+9] |= byte(t[6] << 6)
		r[13*i+10] = byte(t[6] >> 2)
		r[13*i+11] = byte(t[6] >> 10)
		r[13*i+11] |= byte(t[7] << 3)
		r[13*i+12] = byte(t[7] >> 5)
	}
}

// PolyT0Unpack unpacks t0 polynomial (13-bit coefficients).
func PolyT0Unpack(r *Poly, a []byte) {
	for i := 0; i < N/8; i++ {
		r.Coeffs[8*i+0] = int32(a[13*i+0])
		r.Coeffs[8*i+0] |= int32(a[13*i+1]) << 8
		r.Coeffs[8*i+0] &= 0x1FFF

		r.Coeffs[8*i+1] = int32(a[13*i+1]) >> 5
		r.Coeffs[8*i+1] |= int32(a[13*i+2]) << 3
		r.Coeffs[8*i+1] |= int32(a[13*i+3]) << 11
		r.Coeffs[8*i+1] &= 0x1FFF

		r.Coeffs[8*i+2] = int32(a[13*i+3]) >> 2
		r.Coeffs[8*i+2] |= int32(a[13*i+4]) << 6
		r.Coeffs[8*i+2] &= 0x1FFF

		r.Coeffs[8*i+3] = int32(a[13*i+4]) >> 7
		r.Coeffs[8*i+3] |= int32(a[13*i+5]) << 1
		r.Coeffs[8*i+3] |= int32(a[13*i+6]) << 9
		r.Coeffs[8*i+3] &= 0x1FFF

		r.Coeffs[8*i+4] = int32(a[13*i+6]) >> 4
		r.Coeffs[8*i+4] |= int32(a[13*i+7]) << 4
		r.Coeffs[8*i+4] |= int32(a[13*i+8]) << 12
		r.Coeffs[8*i+4] &= 0x1FFF

		r.Coeffs[8*i+5] = int32(a[13*i+8]) >> 1
		r.Coeffs[8*i+5] |= int32(a[13*i+9]) << 7
		r.Coeffs[8*i+5] &= 0x1FFF

		r.Coeffs[8*i+6] = int32(a[13*i+9]) >> 6
		r.Coeffs[8*i+6] |= int32(a[13*i+10]) << 2
		r.Coeffs[8*i+6] |= int32(a[13*i+11]) << 10
		r.Coeffs[8*i+6] &= 0x1FFF

		r.Coeffs[8*i+7] = int32(a[13*i+11]) >> 3
		r.Coeffs[8*i+7] |= int32(a[13*i+12]) << 5
		r.Coeffs[8*i+7] &= 0x1FFF

		for j := 0; j < 8; j++ {
			r.Coeffs[8*i+j] = (1 << (D - 1)) - r.Coeffs[8*i+j]
		}
	}
}

// PolyZPack packs z polynomial with coefficients in [-(GAMMA1-1), GAMMA1].
func PolyZPack(mode Mode, r []byte, a *Poly) {
	gamma1 := mode.Gamma1()
	if gamma1 == (1 << 17) {
		for i := 0; i < N/4; i++ {
			var t [4]uint32
			for j := 0; j < 4; j++ {
				t[j] = uint32(gamma1 - a.Coeffs[4*i+j])
			}
			r[9*i+0] = byte(t[0])
			r[9*i+1] = byte(t[0] >> 8)
			r[9*i+2] = byte((t[0] >> 16) | (t[1] << 2))
			r[9*i+3] = byte(t[1] >> 6)
			r[9*i+4] = byte((t[1] >> 14) | (t[2] << 4))
			r[9*i+5] = byte(t[2] >> 4)
			r[9*i+6] = byte((t[2] >> 12) | (t[3] << 6))
			r[9*i+7] = byte(t[3] >> 2)
			r[9*i+8] = byte(t[3] >> 10)
		}
	} else {
		for i := 0; i < N/2; i++ {
			t0 := uint32(gamma1 - a.Coeffs[2*i+0])
			t1 := uint32(gamma1 - a.Coeffs[2*i+1])
			r[5*i+0] = byte(t0)
			r[5*i+1] = byte(t0 >> 8)
			r[5*i+2] = byte((t0 >> 16) | (t1 << 4))
			r[5*i+3] = byte(t1 >> 4)
			r[5*i+4] = byte(t1 >> 12)
		}
	}
}

// PolyZUnpack unpacks z polynomial.
func PolyZUnpack(mode Mode, r *Poly, a []byte) {
	gamma1 := mode.Gamma1()
	if gamma1 == (1 << 17) {
		for i := 0; i < N/4; i++ {
			r.Coeffs[4*i+0] = int32(a[9*i+0])
			r.Coeffs[4*i+0] |= int32(a[9*i+1]) << 8
			r.Coeffs[4*i+0] |= int32(a[9*i+2]) << 16
			r.Coeffs[4*i+0] &= 0x3FFFF

			r.Coeffs[4*i+1] = int32(a[9*i+2]) >> 2
			r.Coeffs[4*i+1] |= int32(a[9*i+3]) << 6
			r.Coeffs[4*i+1] |= int32(a[9*i+4]) << 14
			r.Coeffs[4*i+1] &= 0x3FFFF

			r.Coeffs[4*i+2] = int32(a[9*i+4]) >> 4
			r.Coeffs[4*i+2] |= int32(a[9*i+5]) << 4
			r.Coeffs[4*i+2] |= int32(a[9*i+6]) << 12
			r.Coeffs[4*i+2] &= 0x3FFFF

			r.Coeffs[4*i+3] = int32(a[9*i+6]) >> 6
			r.Coeffs[4*i+3] |= int32(a[9*i+7]) << 2
			r.Coeffs[4*i+3] |= int32(a[9*i+8]) << 10
			r.Coeffs[4*i+3] &= 0x3FFFF

			for j := 0; j < 4; j++ {
				r.Coeffs[4*i+j] = gamma1 - r.Coeffs[4*i+j]
			}
		}
	} else {
		for i := 0; i < N/2; i++ {
			r.Coeffs[2*i+0] = int32(a[5*i+0])
			r.Coeffs[2*i+0] |= int32(a[5*i+1]) << 8
			r.Coeffs[2*i+0] |= int32(a[5*i+2]) << 16
			r.Coeffs[2*i+0] &= 0xFFFFF

			r.Coeffs[2*i+1] = int32(a[5*i+2]) >> 4
			r.Coeffs[2*i+1] |= int32(a[5*i+3]) << 4
			r.Coeffs[2*i+1] |= int32(a[5*i+4]) << 12
			r.Coeffs[2*i+1] &= 0xFFFFF

			for j := 0; j < 2; j++ {
				r.Coeffs[2*i+j] = gamma1 - r.Coeffs[2*i+j]
			}
		}
	}
}

// PolyW1Pack packs w1 polynomial.
func PolyW1Pack(mode Mode, r []byte, a *Poly) {
	gamma2 := mode.Gamma2()
	if gamma2 == (Q-1)/88 {
		for i := 0; i < N/4; i++ {
			r[3*i+0] = byte(a.Coeffs[4*i+0])
			r[3*i+0] |= byte(a.Coeffs[4*i+1] << 6)
			r[3*i+1] = byte(a.Coeffs[4*i+1] >> 2)
			r[3*i+1] |= byte(a.Coeffs[4*i+2] << 4)
			r[3*i+2] = byte(a.Coeffs[4*i+2] >> 4)
			r[3*i+2] |= byte(a.Coeffs[4*i+3] << 2)
		}
	} else {
		for i := 0; i < N/2; i++ {
			r[i] = byte(a.Coeffs[2*i+0] | (a.Coeffs[2*i+1] << 4))
		}
	}
}
