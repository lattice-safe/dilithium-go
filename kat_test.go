package dilithium

import (
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/sha3"
)

// DeterministicRng matching the C reference's test_vectors.c.
// Initial state: SHAKE128 absorbing empty input, then squeezing.
type DeterministicRng struct {
	hasher sha3.ShakeHash
}

func NewDeterministicRng() *DeterministicRng {
	hasher := sha3.NewShake128()
	return &DeterministicRng{hasher: hasher}
}

func (r *DeterministicRng) Fill(buf []byte) {
	r.hasher.Read(buf)
}

// C reference expected values
const (
	D2_M        = "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
	D2_PK_HASH  = "030116e37de6921adade6bbe80ea940ca24ff5a51153ed0f52c40873f947b9d6"
	D2_SK_HASH  = "798e76ae4ac99e7cb6c3aa4b62951fd9b71b8d86eade71baee5742199e1cef01"
	D2_SIG_HASH = "f90926772cb59d35f2898fcb1e8eab7adf7e0268a53600542781b8064772725f"

	D3_PK_HASH  = "b1043ca0ab60b411fbb1bf6fcc852fd54ee1339d90e877b5b032c3b3d0f167e2"
	D3_SK_HASH  = "320e90c853d708e52b91dc57d29f75fb63b82a1261c1eb491ce5cd1397d872aa"
	D3_SIG_HASH = "4d08b5b628e125dbefaec5c62f105bf6a93c48ca84c62c9b5d7334108f998f21"

	D5_PK_HASH  = "39f5d1b3e15e1d0d5d26571140e5f9d63e6a128751f0581756d9144264328d2f"
	D5_SK_HASH  = "d61328c2ec6eb79eb45990fc95f749fd7834c9e4b44f28bc934b894ed8ebd0dc"
	D5_SIG_HASH = "d154a3ffaefab2526e95324d1ce06e2e96a5cd62599c3a548ac44a9c21142a28"
)

var cCtx = append([]byte("test_vectors"), 0)

func runKatFull(t *testing.T, mode Mode, expectedPk, expectedSk, expectedSig string) {
	rng := NewDeterministicRng()

	var m [32]byte
	rng.Fill(m[:])

	if mode == Dilithium2 {
		mHex := hex.EncodeToString(m[:])
		if mHex != D2_M {
			t.Fatalf("RNG message mismatch")
		}
	}

	var seed [SEEDBYTES]byte
	rng.Fill(seed[:])

	pk, sk := Keypair(mode, &seed)

	var pkHash [32]byte
	Shake256(pkHash[:], pk)
	pkHex := hex.EncodeToString(pkHash[:])
	if pkHex != expectedPk {
		t.Fatalf("%s: public key hash mismatch, expected %s, got %s", mode.FipsName(), expectedPk, pkHex)
	}

	var skHash [32]byte
	Shake256(skHash[:], sk)
	skHex := hex.EncodeToString(skHash[:])
	if skHex != expectedSk {
		t.Fatalf("%s: secret key hash mismatch, expected %s, got %s", mode.FipsName(), expectedSk, skHex)
	}

	var rnd [RNDBYTES]byte
	rng.Fill(rnd[:])

	sig := make([]byte, mode.SignatureBytes())
	SignSignature(mode, sig, m[:], cCtx, &rnd, sk)

	var sigHash [32]byte
	Shake256(sigHash[:], sig)
	sigHex := hex.EncodeToString(sigHash[:])
	if sigHex != expectedSig {
		t.Fatalf("%s: signature hash mismatch, expected %s, got %s", mode.FipsName(), expectedSig, sigHex)
	}

	valid := Verify(mode, sig, m[:], cCtx, pk)
	if !valid {
		t.Fatalf("%s: KAT signature verification failed", mode.FipsName())
	}
}

func TestKatDilithium2Full(t *testing.T) {
	runKatFull(t, Dilithium2, D2_PK_HASH, D2_SK_HASH, D2_SIG_HASH)
}

func TestKatDilithium3Full(t *testing.T) {
	runKatFull(t, Dilithium3, D3_PK_HASH, D3_SK_HASH, D3_SIG_HASH)
}

func TestKatDilithium5Full(t *testing.T) {
	runKatFull(t, Dilithium5, D5_PK_HASH, D5_SK_HASH, D5_SIG_HASH)
}
