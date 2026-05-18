//go:build !amd64

package dilithium

// nttAVX2_8 is a fallback stub for non-amd64 architectures.
func nttAVX2_8(a *[256]int32, zetas *[256]int32) {
	// Not used since dispatch handles this
}
