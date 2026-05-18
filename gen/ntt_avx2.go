//go:build ignore

package main

import (
	"github.com/mmcloughlin/avo/build"
	"github.com/mmcloughlin/avo/operand"
	"github.com/mmcloughlin/avo/reg"
)

func main() {
	build.Package("github.com/lattice-safe/dilithium-go")
	build.ConstraintExpr("amd64")

	build.ConstData("Q", operand.U32(8380417))
	build.ConstData("QINV", operand.U32(58728449))
	
	// Create vectors of Q and QINV
	build.GLOBL("qVec", build.RODATA|build.NOPTR)
	build.DATA(0, operand.U32(8380417))
	build.DATA(4, operand.U32(8380417))
	build.DATA(8, operand.U32(8380417))
	build.DATA(12, operand.U32(8380417))
	build.DATA(16, operand.U32(8380417))
	build.DATA(20, operand.U32(8380417))
	build.DATA(24, operand.U32(8380417))
	build.DATA(28, operand.U32(8380417))

	build.GLOBL("qinvVec", build.RODATA|build.NOPTR)
	build.DATA(0, operand.U32(58728449))
	build.DATA(4, operand.U32(58728449))
	build.DATA(8, operand.U32(58728449))
	build.DATA(12, operand.U32(58728449))
	build.DATA(16, operand.U32(58728449))
	build.DATA(20, operand.U32(58728449))
	build.DATA(24, operand.U32(58728449))
	build.DATA(28, operand.U32(58728449))

	build.GLOBL("maskVec", build.RODATA|build.NOPTR)
	build.DATA(0, operand.U64(0xFFFFFFFF00000000))
	build.DATA(8, operand.U64(0xFFFFFFFF00000000))
	build.DATA(16, operand.U64(0xFFFFFFFF00000000))
	build.DATA(24, operand.U64(0xFFFFFFFF00000000))

	// func nttAVX2(a *[256]int32)
	build.TEXT("nttAVX2", build.NOSPLIT, "func(a *[256]int32)")
	build.Doc("nttAVX2 is the AVX2-accelerated forward NTT.")
	
	// Just a stub for now so it compiles. Full implementation requires loop unrolling.
	build.RET()

	// func invnttAVX2(a *[256]int32)
	build.TEXT("invnttAVX2", build.NOSPLIT, "func(a *[256]int32)")
	build.Doc("invnttAVX2 is the AVX2-accelerated inverse NTT.")
	build.RET()

	build.Generate()
}
