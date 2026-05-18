package dilithium

// Polynomial ring degree.
const N = 256

// Modulus.
const Q = 8380417

// Montgomery constant: Q^{-1} mod 2^32.
const QINV int64 = 58728449 // Q * QINV ≡ 1 (mod 2^32)

// Number of dropped bits from t.
const D = 13

// Root of unity (used in NTT).
const ROOT_OF_UNITY = 1753

// Seed length in bytes.
const SEEDBYTES = 32

// CRH output length in bytes.
const CRHBYTES = 64

// tr length in bytes.
const TRBYTES = 64

// Random bytes for hedged signing.
const RNDBYTES = 32

// Maximum K across all modes (Mode5: K=8).
const K_MAX = 8

// Maximum L across all modes (Mode5: L=7).
const L_MAX = 7

// Packed size for t1 polynomial (10 bits per coefficient).
const POLYT1_PACKEDBYTES = 320

// Packed size for t0 polynomial (13 bits per coefficient).
const POLYT0_PACKEDBYTES = 416

// Mode represents ML-DSA / Dilithium security levels (FIPS 204).
type Mode int

const (
	// ML-DSA-44 (NIST Level 2): K=4, L=4
	Dilithium2 Mode = iota
	// ML-DSA-65 (NIST Level 3): K=6, L=5
	Dilithium3
	// ML-DSA-87 (NIST Level 5): K=8, L=7
	Dilithium5
)

// FIPS 204 type aliases
const (
	ML_DSA_44 = Dilithium2
	ML_DSA_65 = Dilithium3
	ML_DSA_87 = Dilithium5
)

var (
	// OID for id-HashML-DSA-44-with-SHA512 (FIPS 204 §6.2).
	HASH_ML_DSA_44_OID = []byte{0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11}
	// OID for id-HashML-DSA-65-with-SHA512 (FIPS 204 §6.2).
	HASH_ML_DSA_65_OID = []byte{0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12}
	// OID for id-HashML-DSA-87-with-SHA512 (FIPS 204 §6.2).
	HASH_ML_DSA_87_OID = []byte{0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13}
)

// ModeTag returns the byte tag for binary serialization.
func (m Mode) ModeTag() byte {
	switch m {
	case Dilithium2:
		return 0x02
	case Dilithium3:
		return 0x03
	case Dilithium5:
		return 0x05
	}
	return 0
}

// ModeFromTag recovers the mode from a serialization tag.
func ModeFromTag(tag byte) (Mode, bool) {
	switch tag {
	case 0x02:
		return Dilithium2, true
	case 0x03:
		return Dilithium3, true
	case 0x05:
		return Dilithium5, true
	default:
		return 0, false
	}
}

// K returns the number of rows in the matrix A.
func (m Mode) K() int {
	switch m {
	case Dilithium2:
		return 4
	case Dilithium3:
		return 6
	case Dilithium5:
		return 8
	}
	return 0
}

// L returns the number of columns in the matrix A.
func (m Mode) L() int {
	switch m {
	case Dilithium2:
		return 4
	case Dilithium3:
		return 5
	case Dilithium5:
		return 7
	}
	return 0
}

// Eta returns the secret key coefficient bound.
func (m Mode) Eta() int32 {
	switch m {
	case Dilithium2:
		return 2
	case Dilithium3:
		return 4
	case Dilithium5:
		return 2
	}
	return 0
}

// Tau returns the number of ±1 coefficients in the challenge polynomial.
func (m Mode) Tau() int {
	switch m {
	case Dilithium2:
		return 39
	case Dilithium3:
		return 49
	case Dilithium5:
		return 60
	}
	return 0
}

// Beta returns the rejection bound: TAU * ETA.
func (m Mode) Beta() int32 {
	switch m {
	case Dilithium2:
		return 78
	case Dilithium3:
		return 196
	case Dilithium5:
		return 120
	}
	return 0
}

// Gamma1 returns the masking vector coefficient range.
func (m Mode) Gamma1() int32 {
	switch m {
	case Dilithium2:
		return 1 << 17 // 131072
	case Dilithium3:
		return 1 << 19 // 524288
	case Dilithium5:
		return 1 << 19 // 524288
	}
	return 0
}

// Gamma2 returns the low-order rounding range.
func (m Mode) Gamma2() int32 {
	switch m {
	case Dilithium2:
		return (Q - 1) / 88 // 95232
	case Dilithium3:
		return (Q - 1) / 32 // 261888
	case Dilithium5:
		return (Q - 1) / 32 // 261888
	}
	return 0
}

// Omega returns the maximum number of ones in the hint vector.
func (m Mode) Omega() int {
	switch m {
	case Dilithium2:
		return 80
	case Dilithium3:
		return 55
	case Dilithium5:
		return 75
	}
	return 0
}

// Ctildebytes returns the challenge hash output length in bytes.
func (m Mode) Ctildebytes() int {
	switch m {
	case Dilithium2:
		return 32
	case Dilithium3:
		return 48
	case Dilithium5:
		return 64
	}
	return 0
}

// PolyZPackedBytes returns the packed size for z polynomial.
func (m Mode) PolyZPackedBytes() int {
	switch m {
	case Dilithium2:
		return 576
	case Dilithium3:
		return 640
	case Dilithium5:
		return 640
	}
	return 0
}

// PolyW1PackedBytes returns the packed size for w1 polynomial.
func (m Mode) PolyW1PackedBytes() int {
	switch m {
	case Dilithium2:
		return 192
	case Dilithium3:
		return 128
	case Dilithium5:
		return 128
	}
	return 0
}

// PolyEtaPackedBytes returns the packed size for eta polynomial.
func (m Mode) PolyEtaPackedBytes() int {
	switch m {
	case Dilithium2:
		return 96
	case Dilithium3:
		return 128
	case Dilithium5:
		return 96
	}
	return 0
}

// PublicKeyBytes returns the public key size in bytes.
func (m Mode) PublicKeyBytes() int {
	return SEEDBYTES + m.K()*POLYT1_PACKEDBYTES
}

// SecretKeyBytes returns the secret key size in bytes.
func (m Mode) SecretKeyBytes() int {
	return 2*SEEDBYTES + TRBYTES + m.L()*m.PolyEtaPackedBytes() + m.K()*m.PolyEtaPackedBytes() + m.K()*POLYT0_PACKEDBYTES
}

// SignatureBytes returns the signature size in bytes.
func (m Mode) SignatureBytes() int {
	return m.Ctildebytes() + m.L()*m.PolyZPackedBytes() + m.Omega() + m.K()
}

// HashOID returns the HashML-DSA OID for this mode.
func (m Mode) HashOID() []byte {
	switch m {
	case Dilithium2:
		return HASH_ML_DSA_44_OID
	case Dilithium3:
		return HASH_ML_DSA_65_OID
	case Dilithium5:
		return HASH_ML_DSA_87_OID
	}
	return nil
}

// FipsName returns the FIPS 204 algorithm name.
func (m Mode) FipsName() string {
	switch m {
	case Dilithium2:
		return "ML-DSA-44"
	case Dilithium3:
		return "ML-DSA-65"
	case Dilithium5:
		return "ML-DSA-87"
	}
	return ""
}
