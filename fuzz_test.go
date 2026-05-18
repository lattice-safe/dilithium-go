package dilithium

import (
	"testing"
)

func FuzzVerifySignature(f *testing.F) {
	mode := Dilithium2
	kp, _ := Generate(mode)
	msg := []byte("Fuzz testing message")
	ctx := []byte("")
	validSig, _ := kp.Sign(msg, ctx)

	f.Add(kp.PublicKey(), validSig.AsBytes(), msg)

	f.Fuzz(func(t *testing.T, pk, sigBytes, m []byte) {
		// Attempt to verify with fuzzed public key, signature, or message
		// The goal is to ensure it does not panic.
		if len(pk) == mode.PublicKeyBytes() && len(sigBytes) == mode.SignatureBytes() {
			sig := SignatureFromSlice(sigBytes)
			_ = VerifySignature(pk, sig, m, ctx, mode)
		}
	})
}

func FuzzUnpackSk(f *testing.F) {
	mode := Dilithium2
	_, err := Generate(mode)
	if err != nil {
		f.Fatal(err)
	}
	
	// Just use a dummy valid slice length
	validLen := mode.SecretKeyBytes()
	dummySk := make([]byte, validLen)
	f.Add(dummySk)

	f.Fuzz(func(t *testing.T, skBytes []byte) {
		if len(skBytes) == mode.SecretKeyBytes() {
			_, _ = FromBytes(append([]byte{mode.ModeTag()}, skBytes...))
		}
	})
}
