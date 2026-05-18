package dilithium

import (
	"bytes"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	modes := []Mode{Dilithium2, Dilithium3, Dilithium5}

	msg := []byte("Hello, post-quantum world!")
	ctx := []byte("")

	for _, mode := range modes {
		t.Run(mode.FipsName(), func(t *testing.T) {
			kp, err := Generate(mode)
			if err != nil {
				t.Fatalf("Generate failed: %v", err)
			}

			// Pure ML-DSA
			sig, err := kp.Sign(msg, ctx)
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}
			if len(sig.AsBytes()) != mode.SignatureBytes() {
				t.Fatalf("Signature size mismatch: expected %d, got %d", mode.SignatureBytes(), len(sig.AsBytes()))
			}

			valid := VerifySignature(kp.PublicKey(), sig, msg, ctx, mode)
			if !valid {
				t.Fatal("Signature verification failed")
			}

			// HashML-DSA
			sigHash, err := kp.SignPrehash(msg, ctx)
			if err != nil {
				t.Fatalf("SignPrehash failed: %v", err)
			}
			validHash := VerifyPrehash(kp.PublicKey(), sigHash, msg, ctx, mode)
			if !validHash {
				t.Fatal("Prehash signature verification failed")
			}

			// Key serialization round trip
			pkBytes := kp.PublicKeyBytes()
			skBytes := kp.ToBytes()

			kp2, err := FromBytes(skBytes)
			if err != nil {
				t.Fatalf("FromBytes failed: %v", err)
			}

			if !bytes.Equal(kp2.PublicKey(), kp.PublicKey()) {
				t.Fatal("Deserialized public key mismatch")
			}
			if !bytes.Equal(kp2.PrivateKey(), kp.PrivateKey()) {
				t.Fatal("Deserialized private key mismatch")
			}

			_, pkOnly, err := FromPublicKey(pkBytes)
			if err != nil {
				t.Fatalf("FromPublicKey failed: %v", err)
			}
			if !bytes.Equal(pkOnly, kp.PublicKey()) {
				t.Fatal("Public key extraction mismatch")
			}
		})
	}
}

func TestBadSignature(t *testing.T) {
	mode := Dilithium2
	kp, _ := Generate(mode)
	msg := []byte("test")
	sig, _ := kp.Sign(msg, []byte{})

	// Corrupt signature
	corrupted := make([]byte, len(sig.AsBytes()))
	copy(corrupted, sig.AsBytes())
	corrupted[0] ^= 0x01

	valid := VerifySignature(kp.PublicKey(), SignatureFromSlice(corrupted), msg, []byte{}, mode)
	if valid {
		t.Fatal("Corrupted signature was verified as valid")
	}
}
