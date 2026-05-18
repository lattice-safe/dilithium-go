//go:build amd64

package dilithium

//go:generate go run ./gen/ntt_avx2.go -out ntt_avx2_amd64.s

// nttAVX2 is the AVX2-accelerated forward NTT.
// Implemented in ntt_avx2_amd64.s
//go:noescape
func nttAVX2(a *[256]int32)

// invnttAVX2 is the AVX2-accelerated inverse NTT.
// Implemented in ntt_avx2_amd64.s
//go:noescape
func invnttAVX2(a *[256]int32)
