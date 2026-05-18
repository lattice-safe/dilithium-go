package main

import (
	"github.com/mmcloughlin/avo/build"
	"github.com/mmcloughlin/avo/operand"
	"github.com/mmcloughlin/avo/reg"
)

func initGlobals() {
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
}

func montgomeryMulAVX2(zeta, y, q, qinv, mask reg.VecVirtual) reg.VecVirtual {
	aEven := build.YMM()
	build.VPMULDQ(zeta, y, aEven)

	aEvenLo := build.YMM()
	build.VPMULDQ(aEven, qinv, aEvenLo)

	tqEven := build.YMM()
	build.VPMULDQ(aEvenLo, q, tqEven)

	rEven64 := build.YMM()
	build.VPSUBQ(tqEven, aEven, rEven64)

	rEven32 := build.YMM()
	build.VPSRLQ(operand.Imm(32), rEven64, rEven32)

	zetaOdd := build.YMM()
	build.VPSRLQ(operand.Imm(32), zeta, zetaOdd)

	yOdd := build.YMM()
	build.VPSRLQ(operand.Imm(32), y, yOdd)

	aOdd := build.YMM()
	build.VPMULDQ(zetaOdd, yOdd, aOdd)

	aOddLo := build.YMM()
	build.VPMULDQ(aOdd, qinv, aOddLo)

	tqOdd := build.YMM()
	build.VPMULDQ(aOddLo, q, tqOdd)

	rOdd64 := build.YMM()
	build.VPSUBQ(tqOdd, aOdd, rOdd64)

	rOddHi := build.YMM()
	build.VPAND(mask, rOdd64, rOddHi)

	res := build.YMM()
	build.VPOR(rOddHi, rEven32, res)
	return res
}

func butterflyAVX2(aPtr reg.Register, offset1, offset2 int, zeta, q, qinv, mask reg.VecVirtual) {
	x := build.YMM()
	build.VMOVDQU(operand.Mem{Base: aPtr, Disp: offset1}, x)

	y := build.YMM()
	build.VMOVDQU(operand.Mem{Base: aPtr, Disp: offset2}, y)

	t := montgomeryMulAVX2(zeta, y, q, qinv, mask)

	newX := build.YMM()
	build.VPADDD(t, x, newX)
	build.VMOVDQU(newX, operand.Mem{Base: aPtr, Disp: offset1})

	newY := build.YMM()
	build.VPSUBD(t, x, newY)
	build.VMOVDQU(newY, operand.Mem{Base: aPtr, Disp: offset2})
}

func main() {
	build.Package("github.com/lattice-safe/dilithium-go")
	build.ConstraintExpr("amd64")

	initGlobals()

	build.TEXT("nttAVX2_8", build.NOSPLIT, "func(a *[256]int32, zetas *[256]int32)")
	build.Doc("nttAVX2_8 performs AVX2-accelerated forward NTT down to len=8.")
	aPtr := build.Load(build.Param("a"), build.GP64())
	zPtr := build.Load(build.Param("zetas"), build.GP64())

	q := build.YMM()
	build.VMOVDQU(operand.Mem{Symbol: operand.Symbol{Name: "qVec"}}, q)
	qinv := build.YMM()
	build.VMOVDQU(operand.Mem{Symbol: operand.Symbol{Name: "qinvVec"}}, qinv)
	mask := build.YMM()
	build.VMOVDQU(operand.Mem{Symbol: operand.Symbol{Name: "maskVec"}}, mask)

	k := 0
	for l := 128; l >= 8; l >>= 1 {
		start := 0
		for start < 256 {
			k++
			zeta := build.YMM()
			// Load zeta from memory and broadcast
			// PBROADCASTD can broadcast a 32-bit memory location to YMM
			build.VPBROADCASTD(operand.Mem{Base: zPtr, Disp: k * 4}, zeta)

			for j := start; j < start+l; j += 8 {
				offset1 := j * 4
				offset2 := (j + l) * 4
				butterflyAVX2(aPtr, offset1, offset2, zeta, q, qinv, mask)
			}
			start += 2 * l
		}
	}

	build.RET()

	build.Generate()
}
