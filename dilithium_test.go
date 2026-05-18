package dilithium

import (
	"testing"
)



func TestDilithiumSignFail(t *testing.T) {
	kp, err := Generate(Dilithium2)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("test message")
	ctx := []byte("test ctx")

	// Test ctx length
	longCtx := make([]byte, 256)
	_, err = kp.Sign(msg, longCtx)
	if err == nil {
		t.Fatal("expected error for context > 255 bytes")
	}
	_, err = kp.SignPrehash(msg, longCtx)
	if err == nil {
		t.Fatal("expected error for context > 255 bytes")
	}
	_, err = kp.SignDeterministic(msg, longCtx, nil)
	if err == nil {
		t.Fatal("expected error for context > 255 bytes")
	}

	// Test invalid SignSignature returns (ret != 0) by modifying mode secret key length or corrupting sk
	// Actually, easier to just test Deterministic sign success
	var seed [32]byte
	sig, err := kp.SignDeterministic(msg, ctx, &seed)
	if err != nil {
		t.Fatal(err)
	}
	if sig.Len() == 0 || sig.IsEmpty() {
		t.Fatal("expected non-empty signature")
	}

	// Corrupt kp to trigger ret != 0 error
	kp.privkey = kp.privkey[:10]
	_, err = kp.Sign(msg, ctx)
	if err == nil {
		t.Fatal("expected err when privkey corrupted")
	}
	_, err = kp.SignPrehash(msg, ctx)
	if err == nil {
		t.Fatal("expected err when privkey corrupted")
	}
	
	// Test Verify Signature bounds
	valid := VerifySignature(kp.PublicKey()[:10], sig, msg, ctx, Dilithium2)
	if valid {
		t.Fatal("expected false for invalid public key length")
	}
	
	badSig := SignatureFromBytes(sig.AsBytes()[:10])
	valid = VerifySignature(kp.PublicKey(), badSig, msg, ctx, Dilithium2)
	if valid {
		t.Fatal("expected false for invalid signature length")
	}
	
	valid = VerifyPrehash(kp.PublicKey()[:10], sig, msg, ctx, Dilithium2)
	if valid {
		t.Fatal("expected false for invalid public key length")
	}
	
	valid = VerifyPrehash(kp.PublicKey(), badSig, msg, ctx, Dilithium2)
	if valid {
		t.Fatal("expected false for invalid signature length")
	}

	// Test long context directly on lower level sign API
	ret := SignSignature(Dilithium2, sig.AsBytes(), msg, longCtx, &seed, kp.PrivateKey())
	if ret != -1 {
		t.Fatal("expected -1 for long ctx in SignSignature")
	}
	ret = SignHash(Dilithium2, sig.AsBytes(), msg, longCtx, &seed, kp.PrivateKey())
	if ret != -1 {
		t.Fatal("expected -1 for long ctx in SignHash")
	}
	valid = Verify(Dilithium2, sig.AsBytes(), msg, longCtx, kp.PublicKey())
	if valid {
		t.Fatal("expected false for long ctx in Verify")
	}
	valid = VerifyHash(Dilithium2, sig.AsBytes(), msg, longCtx, kp.PublicKey())
	if valid {
		t.Fatal("expected false for long ctx in VerifyHash")
	}

	// VerifyInternal direct error cases
	pre := []byte{0, 0}
	valid = VerifyInternal(Dilithium2, sig.AsBytes(), msg, pre, kp.PublicKey()[:10])
	if valid {
		t.Fatal("expected false for bad pk len in VerifyInternal")
	}

	// Corrupt signature hint to fail UnpackSig
	corruptedSig := SignatureFromSlice(sig.AsBytes())
	corruptedSig.data[corruptedSig.Len()-1] = 0xFF // out of bounds hint end index
	valid = VerifyInternal(Dilithium2, corruptedSig.AsBytes(), msg, pre, kp.PublicKey())
	if valid {
		t.Fatal("expected false for corrupt hint in VerifyInternal")
	}

	// Corrupt signature z to fail PolyVecLChkNorm
	corruptedSigZ := SignatureFromSlice(sig.AsBytes())
	// z is packed right after ctilde. ctilde for Mode2 is 32.
	corruptedSigZ.data[32] = 0xFF 
	corruptedSigZ.data[33] = 0xFF 
	corruptedSigZ.data[34] = 0xFF 
	valid = VerifyInternal(Dilithium2, corruptedSigZ.AsBytes(), msg, pre, kp.PublicKey())
	if valid {
		t.Fatal("expected false for z norm check in VerifyInternal")
	}

	// Corrupt t0 in sk to trigger h norm rejection
	corruptSk := make([]byte, Dilithium2.SecretKeyBytes())
	copy(corruptSk, kp.PrivateKey())
	// t0 offset for Dilithium2 is 896, length is 416 * 4 = 1664 bytes
	for i := 896; i < 896+1664; i++ {
		corruptSk[i] = 0xFF
	}
	corruptKp := &DilithiumKeyPair{privkey: corruptSk, pubkey: kp.PublicKey(), mode: Dilithium2}
	var seed2 [32]byte
	_, _ = corruptKp.SignDeterministic(msg, ctx, &seed2)

	// Corrupt s2 in sk to trigger w0 norm rejection or n > omega
	copy(corruptSk, kp.PrivateKey())
	for i := 512; i < 600; i++ {
		corruptSk[i] = 0xFF
	}
	corruptKp2 := &DilithiumKeyPair{privkey: corruptSk, pubkey: kp.PublicKey(), mode: Dilithium2}
	_, _ = corruptKp2.SignDeterministic(msg, ctx, &seed2)

	valid = VerifyInternal(Dilithium2, sig.AsBytes()[:10], msg, pre, kp.PublicKey())
	if valid {
		t.Fatal("expected false for bad sig len in VerifyInternal")
	}

	// Test Poly ChkNorm bound branch
	p := NewPoly()
	if !p.ChkNorm((Q - 1) / 8 + 1) {
		t.Fatal("expected true for bound > (Q-1)/8")
	}
}

func TestDilithiumKeysAndBytes(t *testing.T) {
	kp, _ := Generate(Dilithium2)
	if kp.Mode() != Dilithium2 {
		t.Fatal("expected Dilithium2")
	}
	
	// Corrupt privkey
	badPrivKey := make([]byte, Dilithium2.SecretKeyBytes())
	badPubKey := make([]byte, Dilithium2.PublicKeyBytes())
	_, err := FromKeys(badPrivKey[:10], badPubKey, Dilithium2)
	if err == nil {
		t.Fatal("expected error for bad privkey len")
	}
	_, err = FromKeys(badPrivKey, badPubKey[:10], Dilithium2)
	if err == nil {
		t.Fatal("expected error for bad pubkey len")
	}
	
	// bad skRho vs pkRho
	badPrivKey[0] = 1
	badPubKey[0] = 2
	_, err = FromKeys(badPrivKey, badPubKey, Dilithium2)
	if err == nil {
		t.Fatal("expected err for mismatched rho")
	}
	
	// bad tr
	badPrivKey[0] = 2 // fix rho
	badPrivKey[64] = 1 // corrupt tr
	_, err = FromKeys(badPrivKey, badPubKey, Dilithium2)
	if err == nil {
		t.Fatal("expected err for mismatched tr")
	}
	
	// FromBytes
	_, err = FromBytes(nil)
	if err == nil {
		t.Fatal("expected err for empty bytes")
	}
	_, err = FromBytes([]byte{99})
	if err == nil {
		t.Fatal("expected err for bad mode")
	}
	_, err = FromBytes([]byte{byte(Dilithium2)})
	if err == nil {
		t.Fatal("expected err for bad len")
	}
	
	// FromPublicKey
	_, _, err = FromPublicKey(nil)
	if err == nil {
		t.Fatal("expected err for empty bytes")
	}
	_, _, err = FromPublicKey([]byte{99})
	if err == nil {
		t.Fatal("expected err for bad mode")
	}
	_, _, err = FromPublicKey([]byte{byte(Dilithium2)})
	if err == nil {
		t.Fatal("expected err for bad len")
	}
	
	// Success cases
	bytes := kp.ToBytes()
	kp2, err := FromBytes(bytes)
	if err != nil {
		t.Fatal(err)
	}
	if kp.Mode() != kp2.Mode() {
		t.Fatal("mode mismatch")
	}
	
	mode, pkCopy, err := FromPublicKey(kp.PublicKeyBytes())
	if err != nil {
		t.Fatal(err)
	}
	if mode != Dilithium2 {
		t.Fatal("mode mismatch")
	}
	if len(pkCopy) != len(kp.PublicKey()) {
		t.Fatal("pk length mismatch")
	}
	
	sig := SignatureFromSlice([]byte("test sig"))
	if sig.Len() != 8 {
		t.Fatal("expected 8")
	}
}
