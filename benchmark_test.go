package dilithium

import (
	"testing"
)

func BenchmarkDilithium(b *testing.B) {
	modes := []Mode{Dilithium2, Dilithium3, Dilithium5}
	msg := []byte("Performance benchmarking message for Dilithium")
	ctx := []byte("")

	for _, mode := range modes {
		b.Run(mode.FipsName(), func(b *testing.B) {
			b.Run("KeyGen", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					_, err := Generate(mode)
					if err != nil {
						b.Fatal(err)
					}
				}
			})

			kp, _ := Generate(mode)

			b.Run("Sign", func(b *testing.B) {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					_, err := kp.Sign(msg, ctx)
					if err != nil {
						b.Fatal(err)
					}
				}
			})

			sig, _ := kp.Sign(msg, ctx)

			b.Run("Verify", func(b *testing.B) {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					valid := VerifySignature(kp.PublicKey(), sig, msg, ctx, mode)
					if !valid {
						b.Fatal("Verify failed")
					}
				}
			})
		})
	}
}
