// Copyright (c) 2020 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package asm

import (
	"fmt"
	"math"
	"testing"

	. "github.com/onsi/gomega"
)

const insnSize = InstructionSize

func TestBlock_Mov64(t *testing.T) {
	RegisterTestingT(t)
	b := NewBlock(false)
	b.Mov64(6, 1)
	Expect(b.insns).To(Equal(Insns{Insn{Instruction: [insnSize]uint8{0xbf, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}}))
}

func TestBlock_MovImm64(t *testing.T) {
	RegisterTestingT(t)
	b := NewBlock(false)
	b.MovImm64(1, 0x1eadbeef)
	Expect(b.insns).To(Equal(Insns{Insn{Instruction: [insnSize]uint8{0xb7, 0x01, 0x00, 0x00, 0xef, 0xbe, 0xad, 0x1e}}}))
}

func TestBlock_JumpLE64(t *testing.T) {
	RegisterTestingT(t)
	b := NewBlock(false)
	b.JumpLE64(1, 2, "foo")
	b.MovImm64(1, 0x1eadbeef)
	b.MovImm64(1, 0x2eadbeef)
	b.LabelNextInsn("foo")
	b.MovImm64(1, 0x3eadbeef)
	insns, err := b.Assemble()
	Expect(err).NotTo(HaveOccurred())

	Expect(insns).To(Equal(Insns{
		Insn{Instruction: [insnSize]uint8{0xbd, 0x21, 0x02, 0x00, 0, 0, 0, 0}},
		Insn{Instruction: [insnSize]uint8{0xb7, 0x01, 0, 0, 0xef, 0xbe, 0xad, 0x1e}},
		Insn{Instruction: [insnSize]uint8{0xb7, 0x01, 0, 0, 0xef, 0xbe, 0xad, 0x2e}},
		Insn{Instruction: [insnSize]uint8{0xb7, 0x01, 0, 0, 0xef, 0xbe, 0xad, 0x3e}},
	}))
}

func TestBlock_Mainline(t *testing.T) {
	RegisterTestingT(t)
	b := NewBlock(false)

	// Pre-amble to the policy program.
	b.Mov64(R6, R1) // Save R1 (context) in R6.
	// Zero-out the map key
	b.MovImm64(R1, 0)       // R1 = 0
	b.StoreStack32(R1, -28) // *(u32 *)(r10 - 28) = r1
	// Get pointer to map key in R2.
	b.Mov64(R2, R10)    // R2 = R10
	b.AddImm64(R2, -28) // R10 += -28
	// Load map file descriptor into R1.
	b.LoadImm64(R1, 0)          // R1 = 0 (64-bit immediate)
	b.Call(HelperMapLookupElem) // Call helper
	// Check return value for NULL.
	b.JumpEqImm64(R0, 0, "drop")

	b.LabelNextInsn("drop")
	b.MovImm64(R0, 2 /* TC_ACT_SHOT */)
	b.Exit()

	insns, err := b.Assemble()
	Expect(err).NotTo(HaveOccurred())

	Expect(insns).To(Equal(Insns{
		Insn{Instruction: [insnSize]uint8{0xbf, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		Insn{Instruction: [insnSize]uint8{0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		Insn{Instruction: [insnSize]uint8{0x63, 0x1a, 0xe4, 0xff, 0x00, 0x00, 0x00, 0x00}},
		Insn{Instruction: [insnSize]uint8{0xbf, 0xa2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		Insn{Instruction: [insnSize]uint8{0x07, 0x02, 0x00, 0x00, 0xe4, 0xff, 0xff, 0xff}},
		Insn{Instruction: [insnSize]uint8{0x18, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		Insn{Instruction: [insnSize]uint8{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		Insn{Instruction: [insnSize]uint8{0x85, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}},
		Insn{Instruction: [insnSize]uint8{0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		Insn{Instruction: [insnSize]uint8{0xb7, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}},
		Insn{Instruction: [insnSize]uint8{0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
	}))
}

func TestSkipUnreachable(t *testing.T) {
	RegisterTestingT(t)
	b := NewBlock(false)

	// Unconditional jump, reachable because at start of program.
	b.Jump("label-0")
	// Not reachable, preceding jump skips it.
	b.Jump("label-1")
	// Reachable: first jump targets this.
	b.LabelNextInsn("label-0")
	b.JumpEq64(R1, R2, "label-2")
	// Reachable: JumpEq64 may fall through.
	b.Exit()
	// Unreachable: Exit doesn't fall through and the jump to label-1 was
	// unreachable too.
	b.LabelNextInsn("label-1")
	b.NoOp()
	// Reachable: from the reachable JumpEq64.
	b.LabelNextInsn("label-2")
	b.Mov64(R1, R2)

	insns, err := b.Assemble()
	Expect(err).NotTo(HaveOccurred())

	Expect(insns).To(Equal(Insns{
		MakeInsn(JumpA, 0, 0, 0, 0),
		MakeInsn(JumpEq64, 1, 2, 1, 0),
		MakeInsn(Exit, 0, 0, 0, 0),
		MakeInsn(Mov64, 1, 2, 0, 0),
	}))
}

func TestLongJump(t *testing.T) {
	RegisterTestingT(t)

	for numNoOps := math.MaxInt16 - 1200; numNoOps < math.MaxInt16+1200; numNoOps++ {
		b := NewBlock(false)
		b.ReserveInstructionCapacity(numNoOps + 5)
		b.JumpEq32(R0, R1, "label")
		for i := 0; i < numNoOps; i++ {
			b.NoOp()
		}
		b.LabelNextInsn("label")
		b.Exit()
		_, err := b.Assemble()
		Expect(err).NotTo(HaveOccurred())
	}
}

func TestJumpToSelf(t *testing.T) {
	RegisterTestingT(t)

	b := NewBlock(false)
	b.LabelNextInsn("self")
	b.Jump("self")
	_, err := b.Assemble()
	Expect(err).To(HaveOccurred())
}

func TestJumpBackwardsTooFar(t *testing.T) {
	RegisterTestingT(t)

	// Jump backwards exactly MinInt16 should be OK.
	b := NewBlock(false)
	b.LabelNextInsn("label")
	// Subtract one because the jump is relative to the instruction
	// after the jump itself.
	safeNumInsns := -math.MinInt16 - 1
	for i := 0; i < safeNumInsns; i++ {
		b.NoOp()
	}
	b.JumpEq32(R0, R1, "label")
	b.MovImm32(R3, 42)
	_, err := b.Assemble()
	Expect(err).NotTo(HaveOccurred())

	// Jump backwards one extra instruction should fail.
	b = NewBlock(false)
	b.LabelNextInsn("label")
	// Subtract one because the jump is relative to the instruction
	// after the jump itself.
	for i := 0; i <= safeNumInsns; i++ {
		b.NoOp()
	}
	b.JumpEq32(R0, R1, "label")
	b.MovImm32(R3, 42)
	_, err = b.Assemble()
	Expect(err).To(HaveOccurred())
}

func TestSingleTrampoline(t *testing.T) {
	RegisterTestingT(t)

	b := NewBlock(false)

	// Make a couple of long jumps, then lots of no-ops to trigger creation of
	// a trampoline.
	b.JumpEq64(R1, R2, "longB")
	b.JumpEq64(R1, R2, "longA")
	for i := 0; i < TrampolineStrideDefault; i++ {
		b.NoOp()
	}

	// Some instructions to jump to...
	b.LabelNextInsn("longA")
	b.Mov64(R1, R2)
	b.Exit()
	b.LabelNextInsn("longB")
	b.Exit()

	insns, err := b.Assemble()
	Expect(err).NotTo(HaveOccurred())
	logSummarisingNoOps(t, insns)

	// Calculate where the trampoline should be.  We sort the jumps within
	// the trampoline for determinacy so longA will be before longB.
	const (
		trampolineStartAddr = TrampolineStrideDefault + iota
		longATrampolineAddr
		longBTrampolineAddr
		trampolineEndAddr
	)
	const (
		jumpToBAddr = iota
		jumpToAAddr
	)
	Expect(insns[jumpToBAddr]).To(Equal(MakeInsn(JumpEq64, R1, R2, longBTrampolineAddr-jumpToBAddr-1, 0)))
	Expect(insns[jumpToAAddr]).To(Equal(MakeInsn(JumpEq64, R1, R2, longATrampolineAddr-jumpToAAddr-1, 0)))

	noOp := MakeInsn(Mov64, R0, R0, 0, 0)
	for i := 2; i < TrampolineStrideDefault-1; i++ {
		Expect(insns[i]).To(Equal(noOp))
	}

	// Jump to skip the trampoline itself.
	Expect(insns[trampolineStartAddr]).To(Equal(MakeInsn(JumpA, 0, 0, 2, 0)))
	// Jump to longA
	Expect(insns[longATrampolineAddr]).To(Equal(MakeInsn(JumpA, 0, 0, 3, 0)))
	// Jump to longB
	Expect(insns[longBTrampolineAddr]).To(Equal(MakeInsn(JumpA, 0, 0, 4, 0)))

	// 2 no-ops fall out of the trampoline interval because there are 2 user
	// instructions in the block.
	Expect(insns[trampolineEndAddr]).To(Equal(noOp))
	Expect(insns[trampolineEndAddr+1]).To(Equal(noOp))

	// longA
	Expect(insns[trampolineEndAddr+2]).To(Equal(MakeInsn(Mov64, R1, R2, 0, 0)))
	Expect(insns[trampolineEndAddr+3]).To(Equal(MakeInsn(Exit, 0, 0, 0, 0)))
	// longB
	Expect(insns[trampolineEndAddr+4]).To(Equal(MakeInsn(Exit, 0, 0, 0, 0)))
}

func TestTrampolineLoadImm64(t *testing.T) {
	RegisterTestingT(t)

	b := NewBlock(false)

	// Make a couple of long jumps, then lots of no-ops to trigger creation of
	// a trampoline.
	b.JumpEq64(R1, R2, "longB")
	b.JumpEq64(R1, R2, "longA")
	for i := 0; i < TrampolineStrideDefault-3; i++ {
		b.NoOp()
	}
	b.LoadImm64(R3, 1234)

	// Some instructions to jump to...
	// Since the trampoline was blocked by the LoadImm64, this longA
	// label actually labels the first instruction of the trampoline, which
	// means we don't get a "longA" jump inside the trampoline.
	b.LabelNextInsn("longA")
	b.Mov64(R1, R2)
	b.Exit()
	b.LabelNextInsn("longB")
	b.Exit()

	insns, err := b.Assemble()
	Expect(err).NotTo(HaveOccurred())
	logSummarisingNoOps(t, insns)

	// Calculate where the trampoline should be.  We sort the jumps within
	// the trampoline for determinacy so longA will be before longB.
	const (
		trampolineStartAddr = TrampolineStrideDefault + 1 + iota
		longBTrampolineAddr
		trampolineEndAddr
	)
	const (
		jumpToBAddr = iota
		jumpToAAddr
	)
	Expect(insns[jumpToBAddr]).To(Equal(MakeInsn(JumpEq64, R1, R2, longBTrampolineAddr-jumpToBAddr-1, 0)))
	Expect(insns[jumpToAAddr]).To(Equal(MakeInsn(JumpEq64, R1, R2, trampolineStartAddr-jumpToAAddr-1, 0)))

	noOp := MakeInsn(Mov64, R0, R0, 0, 0)
	for i := 2; i < TrampolineStrideDefault-1; i++ {
		Expect(insns[i]).To(Equal(noOp))
	}

	// Jump to skip the trampoline itself.
	Expect(insns[trampolineStartAddr]).To(Equal(MakeInsn(JumpA, 0, 0, 1, 0)))
	// Jump to longB
	Expect(insns[longBTrampolineAddr]).To(Equal(MakeInsn(JumpA, 0, 0, 2, 0)))

	// longA
	Expect(insns[trampolineEndAddr]).To(Equal(MakeInsn(Mov64, R1, R2, 0, 0)))
	Expect(insns[trampolineEndAddr+1]).To(Equal(MakeInsn(Exit, 0, 0, 0, 0)))
	// longB
	Expect(insns[trampolineEndAddr+2]).To(Equal(MakeInsn(Exit, 0, 0, 0, 0)))
}

func TestShortJumpAndTrampoline(t *testing.T) {
	RegisterTestingT(t)

	b := NewBlock(false)

	// Make a couple of long jumps, then lots of no-ops to trigger creation of
	// a trampoline.
	b.JumpEq64(R1, R2, "shortA")
	b.JumpEq64(R1, R2, "longA")
	b.LabelNextInsn("shortA")
	for i := 0; i < TrampolineStrideDefault; i++ {
		b.NoOp()
	}

	// Some instructions to jump to...
	b.LabelNextInsn("longA")
	b.Mov64(R1, R2)
	b.Exit()

	insns, err := b.Assemble()
	Expect(err).NotTo(HaveOccurred())
	logSummarisingNoOps(t, insns)

	// Calculate where the trampoline should be.  We sort the jumps within
	// the trampoline for determinacy so longA will be before longB.
	const (
		trampolineStartAddr = TrampolineStrideDefault + iota
		longATrampolineAddr
		trampolineEndAddr
	)
	const (
		jumpToShort = iota
		jumpToLong
	)

	Expect(insns[jumpToShort]).To(Equal(MakeInsn(JumpEq64, R1, R2, 1, 0)))
	Expect(insns[jumpToLong]).To(Equal(MakeInsn(JumpEq64, R1, R2, longATrampolineAddr-jumpToLong-1, 0)))

	noOp := MakeInsn(Mov64, R0, R0, 0, 0)
	for i := 2; i < TrampolineStrideDefault-1; i++ {
		Expect(insns[i]).To(Equal(noOp))
	}

	// Jump to skip the trampoline itself.
	Expect(insns[trampolineStartAddr]).To(Equal(MakeInsn(JumpA, 0, 0, 1, 0)))
	// Jump to longA
	Expect(insns[longATrampolineAddr]).To(Equal(MakeInsn(JumpA, 0, 0, 2, 0)))

	// 2 no-ops fall out of the trampoline interval because there are 2 user
	// instructions in the block.
	Expect(insns[trampolineEndAddr]).To(Equal(noOp))
	Expect(insns[trampolineEndAddr+1]).To(Equal(noOp))

	// longA
	Expect(insns[trampolineEndAddr+2]).To(Equal(MakeInsn(Mov64, R1, R2, 0, 0)))
	Expect(insns[trampolineEndAddr+3]).To(Equal(MakeInsn(Exit, 0, 0, 0, 0)))
}

func TestDoubleTrampoline(t *testing.T) {
	RegisterTestingT(t)

	b := NewBlock(false)

	// Make a couple of long jumps, then lots of no-ops to trigger creation of
	// a trampoline.
	b.JumpEq64(R1, R2, "longB")
	b.JumpEq64(R1, R2, "longA")
	for i := 0; i < TrampolineStrideDefault; i++ {
		b.NoOp()
	}

	// Couple more jumps in the second trampoline interval.  longB will be a
	// double jump only, longA will be a mix, longC will only jump one trampoline.
	b.JumpEq64(R1, R2, "longA")
	b.JumpEq64(R1, R3, "longC")

	for i := 0; i < TrampolineStrideDefault; i++ {
		b.NoOp()
	}

	// Some instructions to jump to...
	b.LabelNextInsn("longA")
	b.Mov64(R1, R2)
	b.Exit()
	b.LabelNextInsn("longB")
	b.Exit()
	b.LabelNextInsn("longC")
	b.Exit()

	insns, err := b.Assemble()
	Expect(err).NotTo(HaveOccurred())
	logSummarisingNoOps(t, insns)

	// Calculate where the trampolines should be.  We sort the jumps within
	// the trampoline for determinacy so longA will be before longB.
	const (
		trampoline0StartAddr = TrampolineStrideDefault + iota
		longATrampoline0Addr
		longBTrampoline0Addr
		trampoline0EndAddr
	)
	const (
		jumpToBAddr = iota
		jumpToAAddr
	)
	const (
		trampoline1StartAddr = TrampolineStrideDefault*2 + iota
		longATrampoline1Addr
		longBTrampoline1Addr
		longCTrampoline1Addr
		trampoline1EndAddr
	)
	const secondJumpToAAddr = trampoline0EndAddr + 2 // After the no-ops that fell out.
	const jumpToCAddr = trampoline0EndAddr + 3

	// Trampoline 1
	// Similar to single-trampoline case but the jumps in the trampoline
	// point to the second trampoline...
	t.Log("Checking trampoline 0...")

	// User-provided jumps should jump to the trampoline.
	Expect(insns[jumpToBAddr]).To(Equal(MakeInsn(JumpEq64, R1, R2, longBTrampoline0Addr-jumpToBAddr-1, 0)))
	Expect(insns[jumpToAAddr]).To(Equal(MakeInsn(JumpEq64, R1, R2, longATrampoline0Addr-jumpToAAddr-1, 0)))
	noOp := MakeInsn(Mov64, R0, R0, 0, 0)
	for i := 2; i < TrampolineStrideDefault-1; i++ {
		Expect(insns[i]).To(Equal(noOp))
	}

	// Jump to skip the trampoline itself.
	Expect(insns[trampoline0StartAddr]).To(Equal(MakeInsn(JumpA, 0, 0, 2, 0)))
	// Jump to longA in the next trampoline...
	Expect(insns[longATrampoline0Addr]).To(Equal(MakeInsn(JumpA, 0, 0, longATrampoline1Addr-longATrampoline0Addr-1, 0)))
	// Jump to longB in the next trampoline...
	Expect(insns[longBTrampoline0Addr]).To(Equal(MakeInsn(JumpA, 0, 0, longBTrampoline1Addr-longBTrampoline0Addr-1, 0)))

	// Couple of no-ops fell out of first block.
	for i := trampoline0EndAddr; i < secondJumpToAAddr; i++ {
		Expect(insns[i]).To(Equal(noOp))
	}

	// Jump to longA
	t.Log("Checking trampoline 1...")
	Expect(insns[secondJumpToAAddr]).To(Equal(MakeInsn(JumpEq64, R1, R2, int16(longATrampoline1Addr-secondJumpToAAddr-1), 0)))
	// Jump to longC
	Expect(insns[jumpToCAddr]).To(Equal(MakeInsn(JumpEq64, R1, R3, int16(longCTrampoline1Addr-jumpToCAddr-1), 0)))
	// No-ops
	for i := jumpToCAddr + 1; i < trampoline1StartAddr; i++ {
		Expect(insns[i]).To(Equal(noOp))
	}

	// Jump to skip the trampoline itself.
	Expect(insns[trampoline1StartAddr]).To(Equal(MakeInsn(JumpA, 0, 0, 3, 0)))
	// Jump to longA,B,C
	Expect(insns[longATrampoline1Addr]).To(Equal(MakeInsn(JumpA, 0, 0, 9, 0)))
	Expect(insns[longBTrampoline1Addr]).To(Equal(MakeInsn(JumpA, 0, 0, 10, 0)))
	Expect(insns[longCTrampoline1Addr]).To(Equal(MakeInsn(JumpA, 0, 0, 10, 0)))

	// 7 no-ops fall out.  2 for the previous no-ops, 2 for the jumps and
	// 3 for the size of the first trampoline.
	for i := trampoline1EndAddr; i < trampoline1EndAddr+7; i++ {
		Expect(insns[i]).To(Equal(noOp))
	}
	// Then we should see mov, exit, exit, exit...

	// longA
	Expect(insns[trampoline1EndAddr+7]).To(Equal(MakeInsn(Mov64, R1, R2, 0, 0)))
	Expect(insns[trampoline1EndAddr+8]).To(Equal(MakeInsn(Exit, 0, 0, 0, 0)))
	// longB
	Expect(insns[trampoline1EndAddr+9]).To(Equal(MakeInsn(Exit, 0, 0, 0, 0)))
	// longC
	Expect(insns[trampoline1EndAddr+10]).To(Equal(MakeInsn(Exit, 0, 0, 0, 0)))
}

func logSummarisingNoOps(t *testing.T, insns Insns) {
	noOps := 0
	for i, insn := range insns {
		if insn.IsNoOp() {
			noOps++
			lastInsn := i == len(insns)-1
			if lastInsn || !insns[i+1].IsNoOp() {
				t.Log(fmt.Sprintf("%d-%d:", i+1-noOps, i), "NoOps")
				noOps = 0
			}
			continue
		}
		t.Log(fmt.Sprintf("%d:", i), insn)
	}
}
