//go:build amd64

package dilithium

//go:generate go run ./gen/ntt_avx2.go -out ntt_avx2_amd64.s

// nttAVX2_8 is the AVX2-accelerated forward NTT down to len=8.
// Implemented in ntt_avx2_amd64.s
//go:noescape
func nttAVX2_8(a *[256]int32, zetas *[256]int32)
