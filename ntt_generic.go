//go:build !amd64

package dilithium

// nttAVX2 is a fallback stub for non-amd64 architectures.
func nttAVX2(a *[256]int32) {
	nttScalar(a)
}

// invnttAVX2 is a fallback stub for non-amd64 architectures.
func invnttAVX2(a *[256]int32) {
	invNTTScalar(a)
}
