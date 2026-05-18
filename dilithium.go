package dilithium

import (
	"crypto/rand"
	"errors"
)

// DilithiumError represents errors returned by the ML-DSA API.
var (
	ErrRandomError  = errors.New("random number generation failed")
	ErrFormatError  = errors.New("invalid format")
	ErrBadSignature = errors.New("invalid signature")
	ErrBadArgument  = errors.New("invalid argument")
	ErrInvalidKey   = errors.New("key validation failed")
)

// DilithiumKeyPair represents an ML-DSA key pair (private key + public key).
type DilithiumKeyPair struct {
	privkey []byte
	pubkey  []byte
	mode    Mode
}

// MlDsaKeyPair is an alias for DilithiumKeyPair (FIPS 204 naming).
type MlDsaKeyPair = DilithiumKeyPair

// DilithiumSignature represents an ML-DSA / Dilithium signature.
type DilithiumSignature struct {
	data []byte
}

// MlDsaSignature is an alias for DilithiumSignature (FIPS 204 naming).
type MlDsaSignature = DilithiumSignature

// Generate creates a new key pair using OS entropy (FIPS 204 §6.1 KeyGen).
func Generate(mode Mode) (*DilithiumKeyPair, error) {
	var seed [SEEDBYTES]byte
	_, err := rand.Read(seed[:])
	if err != nil {
		return nil, ErrRandomError
	}

	kp := GenerateDeterministic(mode, &seed)

	// Zeroize seed
	for i := range seed {
		seed[i] = 0
	}

	return kp, nil
}

// GenerateDeterministic generates a key pair deterministically from a seed.
func GenerateDeterministic(mode Mode, seed *[SEEDBYTES]byte) *DilithiumKeyPair {
	pk, sk := Keypair(mode, seed)
	return &DilithiumKeyPair{
		privkey: sk,
		pubkey:  pk,
		mode:    mode,
	}
}

// Sign signs a message using pure ML-DSA (FIPS 204 §6.1 ML-DSA.Sign).
// Context string ctx is optional (max 255 bytes).
func (kp *DilithiumKeyPair) Sign(msg []byte, ctx []byte) (*DilithiumSignature, error) {
	if len(ctx) > 255 {
		return nil, ErrBadArgument
	}

	var rnd [RNDBYTES]byte
	_, err := rand.Read(rnd[:])
	if err != nil {
		return nil, ErrRandomError
	}

	sig := make([]byte, kp.mode.SignatureBytes())
	ret := SignSignature(kp.mode, sig, msg, ctx, &rnd, kp.privkey)

	// Zeroize rnd
	for i := range rnd {
		rnd[i] = 0
	}

	if ret != 0 {
		return nil, ErrBadArgument
	}

	return &DilithiumSignature{data: sig}, nil
}

// SignPrehash signs a message using HashML-DSA (FIPS 204 §6.2 HashML-DSA.Sign).
// The message is internally hashed with SHA-512 before signing.
func (kp *DilithiumKeyPair) SignPrehash(msg []byte, ctx []byte) (*DilithiumSignature, error) {
	if len(ctx) > 255 {
		return nil, ErrBadArgument
	}

	var rnd [RNDBYTES]byte
	_, err := rand.Read(rnd[:])
	if err != nil {
		return nil, ErrRandomError
	}

	sig := make([]byte, kp.mode.SignatureBytes())
	ret := SignHash(kp.mode, sig, msg, ctx, &rnd, kp.privkey)

	// Zeroize rnd
	for i := range rnd {
		rnd[i] = 0
	}

	if ret != 0 {
		return nil, ErrBadArgument
	}

	return &DilithiumSignature{data: sig}, nil
}

// SignDeterministic signs deterministically (for testing / reproducibility).
func (kp *DilithiumKeyPair) SignDeterministic(msg []byte, ctx []byte, rnd *[RNDBYTES]byte) (*DilithiumSignature, error) {
	if len(ctx) > 255 {
		return nil, ErrBadArgument
	}

	sig := make([]byte, kp.mode.SignatureBytes())
	SignSignature(kp.mode, sig, msg, ctx, rnd, kp.privkey)
	return &DilithiumSignature{data: sig}, nil
}

// Verify verifies a pure ML-DSA signature (FIPS 204 §6.1 ML-DSA.Verify).
func VerifySignature(pk []byte, sig *DilithiumSignature, msg []byte, ctx []byte, mode Mode) bool {
	if len(pk) != mode.PublicKeyBytes() {
		return false
	}
	if len(sig.data) != mode.SignatureBytes() {
		return false
	}
	return Verify(mode, sig.data, msg, ctx, pk)
}

// VerifyPrehash verifies a HashML-DSA signature (FIPS 204 §6.2 HashML-DSA.Verify).
func VerifyPrehash(pk []byte, sig *DilithiumSignature, msg []byte, ctx []byte, mode Mode) bool {
	if len(pk) != mode.PublicKeyBytes() {
		return false
	}
	if len(sig.data) != mode.SignatureBytes() {
		return false
	}
	return VerifyHash(mode, sig.data, msg, ctx, pk)
}

// PublicKey gets the encoded public key bytes.
func (kp *DilithiumKeyPair) PublicKey() []byte {
	return kp.pubkey
}

// PrivateKey gets the encoded private key bytes.
func (kp *DilithiumKeyPair) PrivateKey() []byte {
	return kp.privkey
}

// Mode gets the security mode.
func (kp *DilithiumKeyPair) Mode() Mode {
	return kp.mode
}

// FromKeys reconstructs from private + public key bytes with validation (FIPS 204 §7.1).
func FromKeys(privkey []byte, pubkey []byte, mode Mode) (*DilithiumKeyPair, error) {
	if len(privkey) != mode.SecretKeyBytes() {
		return nil, ErrFormatError
	}
	if len(pubkey) != mode.PublicKeyBytes() {
		return nil, ErrFormatError
	}

	// Validate key consistency
	skRho := privkey[:SEEDBYTES]
	pkRho := pubkey[:SEEDBYTES]
	for i := 0; i < SEEDBYTES; i++ {
		if skRho[i] != pkRho[i] {
			return nil, ErrInvalidKey
		}
	}

	// Validate tr = H(pk)
	trOffset := 2 * SEEDBYTES
	skTr := privkey[trOffset : trOffset+TRBYTES]
	var expectedTr [TRBYTES]byte
	Shake256(expectedTr[:], pubkey)
	for i := 0; i < TRBYTES; i++ {
		if skTr[i] != expectedTr[i] {
			return nil, ErrInvalidKey
		}
	}

	// Copy to prevent mutation issues
	privkeyCopy := make([]byte, len(privkey))
	copy(privkeyCopy, privkey)
	pubkeyCopy := make([]byte, len(pubkey))
	copy(pubkeyCopy, pubkey)

	return &DilithiumKeyPair{
		privkey: privkeyCopy,
		pubkey:  pubkeyCopy,
		mode:    mode,
	}, nil
}

// ToBytes serializes the full key pair to bytes: [mode_tag(1) | pk | sk].
func (kp *DilithiumKeyPair) ToBytes() []byte {
	buf := make([]byte, 0, 1+len(kp.pubkey)+len(kp.privkey))
	buf = append(buf, kp.mode.ModeTag())
	buf = append(buf, kp.pubkey...)
	buf = append(buf, kp.privkey...)
	return buf
}

// FromBytes deserializes a key pair from the format produced by ToBytes.
func FromBytes(data []byte) (*DilithiumKeyPair, error) {
	if len(data) == 0 {
		return nil, ErrFormatError
	}
	mode, ok := ModeFromTag(data[0])
	if !ok {
		return nil, ErrFormatError
	}

	pkLen := mode.PublicKeyBytes()
	skLen := mode.SecretKeyBytes()
	if len(data) != 1+pkLen+skLen {
		return nil, ErrFormatError
	}

	pk := data[1 : 1+pkLen]
	sk := data[1+pkLen:]

	return FromKeys(sk, pk, mode)
}

// PublicKeyBytes exports only the public key bytes with a mode tag: [mode_tag(1) | pk].
func (kp *DilithiumKeyPair) PublicKeyBytes() []byte {
	buf := make([]byte, 0, 1+len(kp.pubkey))
	buf = append(buf, kp.mode.ModeTag())
	buf = append(buf, kp.pubkey...)
	return buf
}

// FromPublicKey creates a verify-only handle from tagged public key bytes.
func FromPublicKey(data []byte) (Mode, []byte, error) {
	if len(data) == 0 {
		return 0, nil, ErrFormatError
	}
	mode, ok := ModeFromTag(data[0])
	if !ok {
		return 0, nil, ErrFormatError
	}
	if len(data) != 1+mode.PublicKeyBytes() {
		return 0, nil, ErrFormatError
	}

	pkCopy := make([]byte, len(data)-1)
	copy(pkCopy, data[1:])

	return mode, pkCopy, nil
}

// AsBytes gets the raw signature bytes.
func (s *DilithiumSignature) AsBytes() []byte {
	return s.data
}

// SignatureFromBytes creates from raw bytes (no validation — use verify to check).
func SignatureFromBytes(data []byte) *DilithiumSignature {
	return &DilithiumSignature{data: data}
}

// SignatureFromSlice creates from a byte slice (copies).
func SignatureFromSlice(data []byte) *DilithiumSignature {
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)
	return &DilithiumSignature{data: dataCopy}
}

// Len returns signature length in bytes.
func (s *DilithiumSignature) Len() int {
	return len(s.data)
}

// IsEmpty returns true if the signature is empty.
func (s *DilithiumSignature) IsEmpty() bool {
	return len(s.data) == 0
}
