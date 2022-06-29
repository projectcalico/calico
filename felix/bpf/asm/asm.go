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

//go:generate stringer -type=OpCode,Reg

import (
	"encoding/binary"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

type OpCode uint8
type Reg int

//noinspection GoUnusedConst
const (
	// Registers.

	// Scratch/return/exit value
	R0 Reg = 0
	// Scratch/arguments.
	R1 Reg = 1
	R2 Reg = 2
	R3 Reg = 3
	R4 Reg = 4
	R5 Reg = 5
	// Callee saves.
	R6 Reg = 6
	R7 Reg = 7
	R8 Reg = 8
	R9 Reg = 9
	// Read-only, frame pointer.
	R10 Reg = 10

	// RPseudoMapFD is special source register value used with LoadImm64
	// to indicate a map file descriptor.
	RPseudoMapFD = 1

	// Opcode parts.

	// Lowest 3 bits of opcode are the instruction class.
	OpClassLoadImm  = 0b00000_000 // 0x0
	OpClassLoadReg  = 0b00000_001 // 0x1
	OpClassStoreImm = 0b00000_010 // 0x2
	OpClassStoreReg = 0b00000_011 // 0x3
	OpClassALU32    = 0b00000_100 // 0x4
	OpClassJump64   = 0b00000_101 // 0x5 64-bit wide operands (jump target always in offset)
	OpClassJump32   = 0b00000_110 // 0x6 32-bit wide operands (jump target always in offset)
	OpClassALU64    = 0b00000_111 // 0x7

	// For memory operations, the upper 3 bits are the mode.
	MemOpModeImm  = 0b000_00_000
	MemOpModeAbs  = 0b001_00_000 // Carry over from cBPF, non-general-purpose
	MemOpModeInd  = 0b010_00_000 // Carry over from cBPF, non-general-purpose
	MemOpModeMem  = 0b011_00_000 // eBPF general memory op.
	MemOpModeXADD = 0b110_00_000 // eBPF general memory op.

	// For memory operations, the middle two bits are the size modifier.
	MemOpSize8  = 0b000_10_000
	MemOpSize16 = 0b000_01_000
	MemOpSize32 = 0b000_00_000
	MemOpSize64 = 0b000_11_000

	// ALU operations have upper 4 bits for the operation
	ALUOpAdd     = 0b0000_0_000 // 0x0
	ALUOpSub     = 0b0001_0_000 // 0x1
	ALUOpMul     = 0b0010_0_000 // 0x2
	ALUOpDiv     = 0b0011_0_000 // 0x3
	ALUOpOr      = 0b0100_0_000 // 0x4
	ALUOpAnd     = 0b0101_0_000 // 0x5
	ALUOpShiftL  = 0b0110_0_000 // 0x6
	ALUOpShiftR  = 0b0111_0_000 // 0x7
	ALUOpNegate  = 0b1000_0_000 // 0x8
	ALUOpMod     = 0b1001_0_000 // 0x9
	ALUOpXOR     = 0b1010_0_000 // 0xa
	ALUOpMov     = 0b1011_0_000 // 0xb
	ALUOpAShiftR = 0b1100_0_000 // 0xc
	ALUOpEndian  = 0b1101_0_000 // 0xd

	// And one bit for the source.
	ALUSrcImm = 0b0000_0_000 // 0x0
	ALUSrcReg = 0b0000_1_000 // 0x8

	// Jumps are similar but they have a different set of operations.
	JumpOpA    = 0b0000_0_000 // 0x00 BPF_JMP only
	JumpOpEq   = 0b0001_0_000 // 0x10
	JumpOpGT   = 0b0010_0_000 // 0x20
	JumpOpGE   = 0b0011_0_000 // 0x30
	JumpOpSet  = 0b0100_0_000 // 0x40
	JumpOpNE   = 0b0101_0_000 // 0x50
	JumpOpSGT  = 0b0110_0_000 // 0x60
	JumpOpSGE  = 0b0111_0_000 // 0x70
	JumpOpCall = 0b1000_0_000 // 0x80 BPF_JMP only
	JumpOpExit = 0b1001_0_000 // 0x90 BPF_JMP only
	JumpOpLT   = 0b1010_0_000 // 0xa0
	JumpOpLE   = 0b1011_0_000 // 0xb0
	JumpOpSLT  = 0b1100_0_000 // 0xc0
	JumpOpSLE  = 0b1101_0_000 // 0xd0

	// Load/store opcodes.
	StoreReg8  OpCode = OpClassStoreReg | MemOpModeMem | MemOpSize8
	StoreReg16 OpCode = OpClassStoreReg | MemOpModeMem | MemOpSize16
	StoreReg32 OpCode = OpClassStoreReg | MemOpModeMem | MemOpSize32
	StoreReg64 OpCode = OpClassStoreReg | MemOpModeMem | MemOpSize64

	// TODO: check these opcodes, should they be OpClassStoreMem with an immediate source instead?
	StoreImm8  OpCode = OpClassStoreImm | MemOpModeImm | MemOpSize8
	StoreImm16 OpCode = OpClassStoreImm | MemOpModeImm | MemOpSize16
	StoreImm32 OpCode = OpClassStoreImm | MemOpModeImm | MemOpSize32
	StoreImm64 OpCode = OpClassStoreImm | MemOpModeImm | MemOpSize64

	LoadReg8  OpCode = OpClassLoadReg | MemOpModeMem | MemOpSize8
	LoadReg16 OpCode = OpClassLoadReg | MemOpModeMem | MemOpSize16
	LoadReg32 OpCode = OpClassLoadReg | MemOpModeMem | MemOpSize32
	LoadReg64 OpCode = OpClassLoadReg | MemOpModeMem | MemOpSize64

	// LoadImm64 loads a 64-bit immediate value; it is a double-length instruction.
	// The immediate is split into two 32-bit halves; the first half is in the
	// first instruction's immediate; the second half is in the second instruction's
	// immediate.  The second instruction's other parts are zet to 0.
	LoadImm64    OpCode = OpClassLoadImm | MemOpModeImm | MemOpSize64
	LoadImm64Pt2 OpCode = 0

	// 64-bit comparison operations.  These do a 64-bit ALU operation between
	// two registers and then do a relative jump to the offset in the instruction.
	// The offset is relative to the next instruction (due to PC auto-increment).
	JumpEq64  OpCode = OpClassJump64 | ALUSrcReg | JumpOpEq
	JumpGT64  OpCode = OpClassJump64 | ALUSrcReg | JumpOpGT
	JumpGE64  OpCode = OpClassJump64 | ALUSrcReg | JumpOpGE
	JumpSet64 OpCode = OpClassJump64 | ALUSrcReg | JumpOpSet
	JumpNE64  OpCode = OpClassJump64 | ALUSrcReg | JumpOpNE
	JumpSGT64 OpCode = OpClassJump64 | ALUSrcReg | JumpOpSGT
	JumpSGE64 OpCode = OpClassJump64 | ALUSrcReg | JumpOpSGE
	JumpLT64  OpCode = OpClassJump64 | ALUSrcReg | JumpOpLT
	JumpLE64  OpCode = OpClassJump64 | ALUSrcReg | JumpOpLE
	JumpSLT64 OpCode = OpClassJump64 | ALUSrcReg | JumpOpSLT
	JumpSLE64 OpCode = OpClassJump64 | ALUSrcReg | JumpOpSLE

	// 64-bit comparison operations.  These do a 64-bit ALU operation between
	// a register and the immediate and then do a relative jump to the offset in
	// the instruction. The offset is relative to the next instruction (due to
	// PC auto-increment).
	JumpEqImm64  OpCode = OpClassJump64 | ALUSrcImm | JumpOpEq
	JumpGTImm64  OpCode = OpClassJump64 | ALUSrcImm | JumpOpGT
	JumpGEImm64  OpCode = OpClassJump64 | ALUSrcImm | JumpOpGE
	JumpSetImm64 OpCode = OpClassJump64 | ALUSrcImm | JumpOpSet
	JumpNEImm64  OpCode = OpClassJump64 | ALUSrcImm | JumpOpNE
	JumpSGTImm64 OpCode = OpClassJump64 | ALUSrcImm | JumpOpSGT
	JumpSGEImm64 OpCode = OpClassJump64 | ALUSrcImm | JumpOpSGE
	JumpLTImm64  OpCode = OpClassJump64 | ALUSrcImm | JumpOpLT
	JumpLEImm64  OpCode = OpClassJump64 | ALUSrcImm | JumpOpLE
	JumpSLTImm64 OpCode = OpClassJump64 | ALUSrcImm | JumpOpSLT
	JumpSLEImm64 OpCode = OpClassJump64 | ALUSrcImm | JumpOpSLE

	// JumpA: Unconditional jump.
	JumpA OpCode = OpClassJump64 | ALUSrcImm | JumpOpA

	// Call calls the helper function with ID stored in the immediate.
	Call OpCode = OpClassJump64 | ALUSrcImm | JumpOpCall
	// Exit exits the program, has no arguments, the return value is in R0.
	Exit OpCode = OpClassJump64 | ALUSrcImm | JumpOpExit

	// 32-bit comparison operations.  These do a 32-bit ALU operation between
	// two registers and then do a relative jump to the offset in the instruction.
	// The offset is relative to the next instruction (due to PC auto-increment).
	JumpEq32  OpCode = OpClassJump32 | ALUSrcReg | JumpOpEq
	JumpGT32  OpCode = OpClassJump32 | ALUSrcReg | JumpOpGT
	JumpGE32  OpCode = OpClassJump32 | ALUSrcReg | JumpOpGE
	JumpSet32 OpCode = OpClassJump32 | ALUSrcReg | JumpOpSet
	JumpNE32  OpCode = OpClassJump32 | ALUSrcReg | JumpOpNE
	JumpSGT32 OpCode = OpClassJump32 | ALUSrcReg | JumpOpSGT
	JumpSGE32 OpCode = OpClassJump32 | ALUSrcReg | JumpOpSGE
	JumpLT32  OpCode = OpClassJump32 | ALUSrcReg | JumpOpLT
	JumpLE32  OpCode = OpClassJump32 | ALUSrcReg | JumpOpLE
	JumpSLT32 OpCode = OpClassJump32 | ALUSrcReg | JumpOpSLT
	JumpSLE32 OpCode = OpClassJump32 | ALUSrcReg | JumpOpSLE

	// 32-bit comparison operations.  These do a 32-bit ALU operation between
	// a register and the immediate and then do a relative jump to the offset in
	// the instruction. The offset is relative to the next instruction (due to
	// PC auto-increment).
	JumpEqImm32  OpCode = OpClassJump32 | ALUSrcImm | JumpOpEq
	JumpGTImm32  OpCode = OpClassJump32 | ALUSrcImm | JumpOpGT
	JumpGEImm32  OpCode = OpClassJump32 | ALUSrcImm | JumpOpGE
	JumpSetImm32 OpCode = OpClassJump32 | ALUSrcImm | JumpOpSet
	JumpNEImm32  OpCode = OpClassJump32 | ALUSrcImm | JumpOpNE
	JumpSGTImm32 OpCode = OpClassJump32 | ALUSrcImm | JumpOpSGT
	JumpSGEImm32 OpCode = OpClassJump32 | ALUSrcImm | JumpOpSGE
	JumpLTImm32  OpCode = OpClassJump32 | ALUSrcImm | JumpOpLT
	JumpLEImm32  OpCode = OpClassJump32 | ALUSrcImm | JumpOpLE
	JumpSLTImm32 OpCode = OpClassJump32 | ALUSrcImm | JumpOpSLT
	JumpSLEImm32 OpCode = OpClassJump32 | ALUSrcImm | JumpOpSLE

	// 64-bit ALU operations between a pair of registers, specified as src and dst,
	// the result of the operation is stored in dst.
	Add64     OpCode = OpClassALU64 | ALUSrcReg | ALUOpAdd
	Sub64     OpCode = OpClassALU64 | ALUSrcReg | ALUOpSub
	Mul64     OpCode = OpClassALU64 | ALUSrcReg | ALUOpMul
	Div64     OpCode = OpClassALU64 | ALUSrcReg | ALUOpDiv
	Or64      OpCode = OpClassALU64 | ALUSrcReg | ALUOpOr
	And64     OpCode = OpClassALU64 | ALUSrcReg | ALUOpAnd
	ShiftL64  OpCode = OpClassALU64 | ALUSrcReg | ALUOpShiftL
	ShiftR64  OpCode = OpClassALU64 | ALUSrcReg | ALUOpShiftR
	Negate64  OpCode = OpClassALU64 | ALUSrcReg | ALUOpNegate
	Mod64     OpCode = OpClassALU64 | ALUSrcReg | ALUOpMod
	XOR64     OpCode = OpClassALU64 | ALUSrcReg | ALUOpXOR
	Mov64     OpCode = OpClassALU64 | ALUSrcReg | ALUOpMov
	AShiftR64 OpCode = OpClassALU64 | ALUSrcReg | ALUOpAShiftR
	Endian64  OpCode = OpClassALU64 | ALUSrcReg | ALUOpEndian

	// 32-bit ALU operations between a pair of registers, specified as src and dst,
	// the result of the operation is stored in dst.
	Add32     OpCode = OpClassALU32 | ALUSrcReg | ALUOpAdd
	Sub32     OpCode = OpClassALU32 | ALUSrcReg | ALUOpSub
	Mul32     OpCode = OpClassALU32 | ALUSrcReg | ALUOpMul
	Div32     OpCode = OpClassALU32 | ALUSrcReg | ALUOpDiv
	Or32      OpCode = OpClassALU32 | ALUSrcReg | ALUOpOr
	And32     OpCode = OpClassALU32 | ALUSrcReg | ALUOpAnd
	ShiftL32  OpCode = OpClassALU32 | ALUSrcReg | ALUOpShiftL
	ShiftR32  OpCode = OpClassALU32 | ALUSrcReg | ALUOpShiftR
	Negate32  OpCode = OpClassALU32 | ALUSrcReg | ALUOpNegate
	Mod32     OpCode = OpClassALU32 | ALUSrcReg | ALUOpMod
	XOR32     OpCode = OpClassALU32 | ALUSrcReg | ALUOpXOR
	Mov32     OpCode = OpClassALU32 | ALUSrcReg | ALUOpMov
	AShiftR32 OpCode = OpClassALU32 | ALUSrcReg | ALUOpAShiftR
	Endian32  OpCode = OpClassALU32 | ALUSrcReg | ALUOpEndian

	// 64-bit ALU operations between a register and immediate value.  Note: immediate is only
	// 32-bit.
	AddImm64     OpCode = OpClassALU64 | ALUSrcImm | ALUOpAdd
	SubImm64     OpCode = OpClassALU64 | ALUSrcImm | ALUOpSub
	MulImm64     OpCode = OpClassALU64 | ALUSrcImm | ALUOpMul
	DivImm64     OpCode = OpClassALU64 | ALUSrcImm | ALUOpDiv
	OrImm64      OpCode = OpClassALU64 | ALUSrcImm | ALUOpOr
	AndImm64     OpCode = OpClassALU64 | ALUSrcImm | ALUOpAnd
	ShiftLImm64  OpCode = OpClassALU64 | ALUSrcImm | ALUOpShiftL
	ShiftRImm64  OpCode = OpClassALU64 | ALUSrcImm | ALUOpShiftR
	ModImm64     OpCode = OpClassALU64 | ALUSrcImm | ALUOpMod
	XORImm64     OpCode = OpClassALU64 | ALUSrcImm | ALUOpXOR
	MovImm64     OpCode = OpClassALU64 | ALUSrcImm | ALUOpMov
	AShiftRImm64 OpCode = OpClassALU64 | ALUSrcImm | ALUOpAShiftR
	EndianImm64  OpCode = OpClassALU64 | ALUSrcImm | ALUOpEndian

	// 32-bit ALU operations between a register and immediate value.
	AddImm32     OpCode = OpClassALU32 | ALUSrcImm | ALUOpAdd
	SubImm32     OpCode = OpClassALU32 | ALUSrcImm | ALUOpSub
	MulImm32     OpCode = OpClassALU32 | ALUSrcImm | ALUOpMul
	DivImm32     OpCode = OpClassALU32 | ALUSrcImm | ALUOpDiv
	OrImm32      OpCode = OpClassALU32 | ALUSrcImm | ALUOpOr
	AndImm32     OpCode = OpClassALU32 | ALUSrcImm | ALUOpAnd
	ShiftLImm32  OpCode = OpClassALU32 | ALUSrcImm | ALUOpShiftL
	ShiftRImm32  OpCode = OpClassALU32 | ALUSrcImm | ALUOpShiftR
	ModImm32     OpCode = OpClassALU32 | ALUSrcImm | ALUOpMod
	XORImm32     OpCode = OpClassALU32 | ALUSrcImm | ALUOpXOR
	MovImm32     OpCode = OpClassALU32 | ALUSrcImm | ALUOpMov
	AShiftRImm32 OpCode = OpClassALU32 | ALUSrcImm | ALUOpAShiftR
	EndianImm32  OpCode = OpClassALU32 | ALUSrcImm | ALUOpEndian
)

const insnSize = 8

type Insn struct {
	Instruction [insnSize]uint8 `json:"inst"`
	Labels      []string        `json:"labels,omitempty"`
	Comments    []string        `json:"comments,omitempty"`
}

type Insns []Insn

func (ns Insns) AsBytes() []byte {
	bs := make([]byte, 0, len(ns)*insnSize)
	for _, n := range ns {
		bs = append(bs, n.Instruction[:]...)
	}
	return bs
}

func MakeInsn(opcode OpCode, dst, src Reg, offset int16, imm int32) Insn {
	insn := Insn{}
	insn.Instruction = [8]uint8{uint8(opcode), uint8(src<<4 | dst), 0, 0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint16(insn.Instruction[2:4], uint16(offset))
	binary.LittleEndian.PutUint32(insn.Instruction[4:], uint32(imm))
	return insn
}

func (n Insn) String() string {
	return fmt.Sprintf("%v dst=%v src=%v off=%v imm=%#08x/%d", n.OpCode(), n.Dst(), n.Src(), n.Off(), uint32(n.Imm()), n.Imm())
}

func (n Insn) OpCode() OpCode {
	return OpCode(n.Instruction[0])
}

func (n Insn) Dst() Reg {
	return Reg(n.Instruction[1] & 0xf)
}

func (n Insn) Src() Reg {
	return Reg((n.Instruction[1] >> 4) & 0xf)
}

func (n Insn) Off() int16 {
	return int16(binary.LittleEndian.Uint16(n.Instruction[2:4]))
}

func (n Insn) Imm() int32 {
	return int32(binary.LittleEndian.Uint32(n.Instruction[4:8]))
}

type Block struct {
	insns              Insns
	fixUps             []fixUp
	labelToInsnIdx     map[string]int
	insnIdxToLabels    map[int][]string
	insnIdxToComments  map[int][]string
	inUseJumpTargets   set.Set
	policyDebugEnabled bool
}

func NewBlock(policyDebugEnabled bool) *Block {
	return &Block{
		labelToInsnIdx:     map[string]int{},
		insnIdxToLabels:    map[int][]string{},
		inUseJumpTargets:   set.New(),
		insnIdxToComments:  map[int][]string{},
		policyDebugEnabled: policyDebugEnabled,
	}
}

type fixUp struct {
	label       string
	origInsnIdx int
}

func (b *Block) And32(dst, src Reg) {
	b.add(And32, dst, src, 0, 0)
}

func (b *Block) AndImm32(dst Reg, imm int32) {
	b.add(AndImm32, dst, 0, 0, imm)
}

func (b *Block) AndImm64(dst Reg, imm int32) {
	b.add(AndImm64, dst, 0, 0, imm)
}

func (b *Block) ShiftRImm64(dst Reg, imm int32) {
	b.add(ShiftRImm64, dst, 0, 0, imm)
}

// LoadImm64 loads a 64-bit immediate into a register.  Double-length instruction.
func (b *Block) LoadImm64(dst Reg, imm int64) {
	// LoadImm64 is the only double-length instruction.
	b.add(LoadImm64, dst, 0, 0, int32(imm))
	b.add(LoadImm64Pt2, 0, 0, 0, int32(imm>>32))
}

// LoadMapFD special variant of LoadImm64 for loading map FDs.
func (b *Block) LoadMapFD(dst Reg, fd uint32) {
	// Have to use LoadImm64 with the special pseudo-register even though FDs are only 32 bits.
	b.add(LoadImm64, dst, RPseudoMapFD, 0, int32(fd))
	b.add(LoadImm64Pt2, 0, 0, 0, 0)
}

func (b *Block) Load8(dst Reg, ptrReg Reg, offset int16) {
	b.add(LoadReg8, dst, ptrReg, offset, 0)
}

func (b *Block) Load16(dst Reg, ptrReg Reg, offset int16) {
	b.add(LoadReg16, dst, ptrReg, offset, 0)
}

func (b *Block) Load32(dst Reg, ptrReg Reg, offset int16) {
	b.add(LoadReg32, dst, ptrReg, offset, 0)
}

func (b *Block) Load64(dst Reg, ptrReg Reg, offset int16) {
	b.add(LoadReg64, dst, ptrReg, offset, 0)
}

func (b *Block) Store8(dst Reg, ptrReg Reg, offset int16) {
	b.add(StoreReg8, dst, ptrReg, offset, 0)
}

func (b *Block) Store16(dst Reg, ptrReg Reg, offset int16) {
	b.add(StoreReg16, dst, ptrReg, offset, 0)
}

func (b *Block) Store32(dst Reg, ptrReg Reg, offset int16) {
	b.add(StoreReg32, dst, ptrReg, offset, 0)
}

func (b *Block) Store64(dst Reg, ptrReg Reg, offset int16) {
	b.add(StoreReg64, dst, ptrReg, offset, 0)
}

func (b *Block) LoadStack8(dst Reg, offset int16) {
	b.Load8(dst, R10, offset)
}

func (b *Block) LoadStack16(dst Reg, offset int16) {
	b.Load16(dst, R10, offset)
}

func (b *Block) LoadStack32(dst Reg, offset int16) {
	b.Load32(dst, R10, offset)
}

func (b *Block) LoadStack64(dst Reg, offset int16) {
	b.Load64(dst, R10, offset)
}

func (b *Block) StoreStack8(src Reg, offset int16) {
	b.add(StoreReg8, R10, src, offset, 0)
}

func (b *Block) StoreStack16(src Reg, offset int16) {
	b.add(StoreReg16, R10, src, offset, 0)
}

func (b *Block) StoreStack32(src Reg, offset int16) {
	b.add(StoreReg32, R10, src, offset, 0)
}

func (b *Block) StoreStack64(src Reg, offset int16) {
	b.add(StoreReg64, R10, src, offset, 0)
}

func (b *Block) Mov64(dst, src Reg) {
	b.add(Mov64, dst, src, 0, 0)
}

func (b *Block) MovImm64(dst Reg, imm int32) {
	b.add(MovImm64, dst, 0, 0, imm)
}

func (b *Block) MovImm32(dst Reg, imm int32) {
	b.add(MovImm32, dst, 0, 0, imm)
}

func (b *Block) AddImm64(dst Reg, imm int32) {
	b.add(AddImm64, dst, 0, 0, imm)
}

func (b *Block) Jump(label string) {
	b.addWithOffsetFixup(JumpA, 0, 0, label, 0)
}

func (b *Block) JumpEq64(ra, rb Reg, label string) {
	b.addWithOffsetFixup(JumpEq64, ra, rb, label, 0)
}

func (b *Block) JumpEqImm64(ra Reg, imm int32, label string) {
	b.addWithOffsetFixup(JumpEqImm64, ra, 0, label, imm)
}

func (b *Block) JumpLEImm64(ra Reg, imm int32, label string) {
	b.addWithOffsetFixup(JumpLEImm64, ra, 0, label, imm)
}

func (b *Block) JumpLTImm64(ra Reg, imm int32, label string) {
	b.addWithOffsetFixup(JumpLTImm64, ra, 0, label, imm)
}

func (b *Block) JumpGEImm64(ra Reg, imm int32, label string) {
	b.addWithOffsetFixup(JumpGEImm64, ra, 0, label, imm)
}

func (b *Block) JumpNEImm64(ra Reg, imm int32, label string) {
	b.addWithOffsetFixup(JumpNEImm64, ra, 0, label, imm)
}

func (b *Block) JumpLE64(ra, rb Reg, label string) {
	b.addWithOffsetFixup(JumpLE64, ra, rb, label, 0)
}

func (b *Block) JumpLT64(ra, rb Reg, label string) {
	b.addWithOffsetFixup(JumpLT64, ra, rb, label, 0)
}

func (b *Block) JumpGE64(ra, rb Reg, label string) {
	b.addWithOffsetFixup(JumpGE64, ra, rb, label, 0)
}

func (b *Block) JumpGT64(ra, rb Reg, label string) {
	b.addWithOffsetFixup(JumpGT64, ra, rb, label, 0)
}

func (b *Block) JumpEq32(ra, rb Reg, label string) {
	b.addWithOffsetFixup(JumpEq32, ra, rb, label, 0)
}

func (b *Block) JumpEqImm32(ra Reg, imm int32, label string) {
	b.addWithOffsetFixup(JumpEqImm32, ra, 0, label, imm)
}

func (b *Block) JumpLE32(ra, rb Reg, label string) {
	b.addWithOffsetFixup(JumpLE32, ra, rb, label, 0)
}

func (b *Block) JumpLT32(ra, rb Reg, label string) {
	b.addWithOffsetFixup(JumpLT32, ra, rb, label, 0)
}

func (b *Block) JumpGE32(ra, rb Reg, label string) {
	b.addWithOffsetFixup(JumpGE32, ra, rb, label, 0)
}

func (b *Block) JumpGT32(ra, rb Reg, label string) {
	b.addWithOffsetFixup(JumpGT32, ra, rb, label, 0)
}

func (b *Block) Call(helperID Helper) {
	b.add(Call, 0, 0, 0, int32(helperID))
}

func (b *Block) Exit() {
	b.add(Exit, 0, 0, 0, 0)
}

func (b *Block) add(opcode OpCode, dst, src Reg, offset int16, imm int32) Insn {
	insn := MakeInsn(opcode, dst, src, offset, imm)
	b.addInsn(insn)
	return insn
}

func (b *Block) addWithOffsetFixup(opcode OpCode, dst, src Reg, offsetLabel string, imm int32) Insn {
	insn := MakeInsn(opcode, dst, src, 0, imm)
	b.addInsnWithOffsetFixup(insn, offsetLabel)
	return insn
}

func (b *Block) addInsn(insn Insn) {
	b.addInsnWithOffsetFixup(insn, "")
}

type OffsetFixer func(origInsn Insn) Insn

func (b *Block) addInsnWithOffsetFixup(insn Insn, targetLabel string) {
	insnLabel := strings.Join(b.insnIdxToLabels[len(b.insns)], ",")
	if !b.nextInsnReachble() {
		log.Debugf("Asm: %v UU:    %v [UNREACHABLE]", insnLabel, insn)
		for _, l := range b.insnIdxToLabels[len(b.insns)] {
			delete(b.labelToInsnIdx, l)
		}
		delete(b.insnIdxToLabels, len(b.insns))
		return
	}
	var comment string
	if targetLabel != "" {
		comment = " -> " + targetLabel
	}
	log.Debugf("Asm: %v %d:    %v%s", insnLabel, len(b.insns), insn, comment)
	b.insns = append(b.insns, insn)
	if targetLabel != "" {
		b.inUseJumpTargets.Add(targetLabel)
		b.fixUps = append(b.fixUps, fixUp{label: targetLabel, origInsnIdx: len(b.insns) - 1})
	}
}

func (b *Block) TargetIsUsed(label string) bool {
	return b.inUseJumpTargets.Contains(label)
}

func (b *Block) Assemble() (Insns, error) {
	for _, f := range b.fixUps {
		labelIdx, ok := b.labelToInsnIdx[f.label]
		if !ok {
			return nil, fmt.Errorf("missing label: %s", f.label)
		}
		// Offset is relative to the next instruction since the PC is auto-incremented.
		offset := labelIdx - f.origInsnIdx - 1
		binary.LittleEndian.PutUint16(b.insns[f.origInsnIdx].Instruction[2:4], uint16(offset))
	}

	if b.policyDebugEnabled {
		for idx := range b.insns {
			if labels, ok := b.insnIdxToLabels[idx]; ok {
				b.insns[idx].Labels = append(b.insns[idx].Labels, labels...)
			}
			if comments, ok := b.insnIdxToComments[idx]; ok {
				b.insns[idx].Comments = append(b.insns[idx].Comments, comments...)
			}
		}
	}

	return b.insns, nil
}

func (b *Block) LabelNextInsn(label string) {
	b.labelToInsnIdx[label] = len(b.insns)
	b.insnIdxToLabels[len(b.insns)] = append(b.insnIdxToLabels[len(b.insns)], label)
}

func (b *Block) WriteComments(comment string) {
	if b.policyDebugEnabled {
		b.insnIdxToComments[len(b.insns)] = append(b.insnIdxToComments[len(b.insns)], comment)
	}
}

func (b *Block) nextInsnReachble() bool {
	if len(b.insns) == 0 {
		return true // First instruction is always reachable.
	}
	for _, l := range b.insnIdxToLabels[len(b.insns)] {
		if b.inUseJumpTargets.Contains(l) {
			return true // Previous instruction jumps to this one, we're reachable.
		}
	}
	lastInsn := b.insns[len(b.insns)-1]
	switch lastInsn.OpCode() {
	case JumpA, Exit:
		// Previous instruction jumps or returns and it doesn't jump here so we're not reachable.
		return false
	default:
		return true
	}
}
