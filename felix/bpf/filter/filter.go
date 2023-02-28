// Copyright (c) 2022 Tigera, Inc. All rights reserved.
//
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

package filter

import (
	"encoding/binary"
	"fmt"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/projectcalico/calico/felix/bpf/asm"
	"github.com/projectcalico/calico/felix/bpf/maps"
	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
)

func New(linkType layers.LinkType, minLen int, expression string, jumpMapFD maps.FD) (asm.Insns, error) {
	return newFilter(linkType, minLen, expression, jumpMapFD, false)
}

func NewStandAlone(linkType layers.LinkType, minLen int, expression string) (asm.Insns, error) {
	return newFilter(linkType, minLen, expression, 0, true)
}

func newFilter(
	linkType layers.LinkType,
	minLen int,
	expression string,
	jumpMapFD maps.FD,
	standAlone bool) (asm.Insns, error) {

	b := asm.NewBlock(true)

	insns, err := pcap.CompileBPFFilter(linkType, minLen, expression)
	if err != nil {
		return nil, fmt.Errorf("pcap compile filter: %w", err)
	}

	programHeader(b, minLen)

	err = cBPF2eBPF(b, insns, linkType)
	if err != nil {
		return nil, fmt.Errorf("cbpf to ebpf conversion: %w", err)
	}

	if standAlone {
		programFooterStandAlone(b)
	} else {
		programFooter(b, jumpMapFD, expression)
	}

	ebpf, err := b.Assemble()

	if err != nil {
		return nil, err
	}

	return ebpf, nil
}

func Printk(b *asm.Block, msg string) {
	l := len(msg) + 8 - (len(msg) % 8)
	bytes := []byte(msg)
	bytes = append(bytes, []byte{0, 0, 0, 0, 0, 0, 0, 0}...)

	for offset := l; offset > 0; offset -= 8 {
		imm := binary.LittleEndian.Uint64(bytes[offset-8 : offset])
		b.LoadImm64(asm.R2, int64(imm))
		b.Store64(asm.R10, asm.R2, asm.FieldOffset{Offset: int16(offset - l - 8), Field: "stack"})
	}

	b.Mov64(asm.R1, asm.R10)
	b.AddImm64(asm.R1, int32(-l))
	b.LoadImm64(asm.R2, int64(len(msg)+1))
	b.Call(asm.HelperTracePrintk)
}

func programHeader(b *asm.Block, minLen int) {
	// Preamble to the policy program.
	b.LabelNextInsn("start")
	b.Mov64(asm.R6, asm.R1) // Save R1 (context) in R6.

	b.AddComment("Make sure enough data is accessible")
	b.Load32(asm.R1, asm.R6, asm.SkbuffOffsetLen)
	b.JumpLTImm64(asm.R1, int32(minLen), "exit")

	// Load data pointer to R7
	b.Load32(asm.R7, asm.R6, asm.SkbuffOffsetData)
	b.Load32(asm.R8, asm.R6, asm.SkbuffOffsetDataEnd)
	b.Mov64(asm.R3, asm.R7)
	b.AddImm64(asm.R3, int32(minLen))
	b.JumpLE64(asm.R3, asm.R8, "filter")

	// Pull data if do not have enough
	b.Mov64(asm.R1, asm.R6) // ctx -> R1
	b.LoadImm64(asm.R2, int64(minLen))
	b.Call(asm.HelperSkbPullData)
	b.JumpNEImm64(asm.R0, 0, "exit")
	b.Load32(asm.R7, asm.R6, asm.SkbuffOffsetData)
	b.Load32(asm.R8, asm.R6, asm.SkbuffOffsetDataEnd)
	b.Mov64(asm.R3, asm.R7)
	b.AddImm64(asm.R3, int32(minLen))
	b.JumpGT64(asm.R3, asm.R8, "exit")

	b.LabelNextInsn("filter")
	// Zero R1 (A) and R2 (X)
	b.LoadImm64(asm.R1, 0)
	b.LoadImm64(asm.R2, 0)
}

func programFooterStandAlone(b *asm.Block) {
	b.LabelNextInsn("miss")
	b.LabelNextInsn("exit")
	b.MovImm64(asm.R0, 2 /* TC_ACT_SHOT */)
	b.Exit()

	b.LabelNextInsn("hit")
	b.MovImm64(asm.R0, int32(-1) /* TC_ACT_UNSPEC */)
	b.Exit()
}

func programFooter(b *asm.Block, fd maps.FD, expression string) {
	b.LabelNextInsn("hit")

	// Execute the tail call to log program
	b.Mov64(asm.R1, asm.R6)                   // First arg is the context.
	b.LoadMapFD(asm.R2, uint32(fd))           // Second arg is the map.
	b.MovImm32(asm.R3, tcdefs.ProgIndexDebug) // Third arg is the index (rather than a pointer to the index).
	b.Call(asm.HelperTailCall)

	// If we do not have a program for logging, fall through to no logs.

	b.LabelNextInsn("miss")
	b.LabelNextInsn("exit")

	// Execute the tail call to no-log program
	b.Mov64(asm.R1, asm.R6)                     // First arg is the context.
	b.LoadMapFD(asm.R2, uint32(fd))             // Second arg is the map.
	b.MovImm32(asm.R3, tcdefs.ProgIndexNoDebug) // Third arg is the index (rather than a pointer to the index).
	b.Call(asm.HelperTailCall)

	// Fall through after not being able to make a call, let the packet through.
	b.MovImm64(asm.R0, int32(-1) /* TC_ACT_UNSPEC */)
	b.Exit()
}

func fromBE(b *asm.Block, size uint8) {
	sz := int32(64)
	switch asm.OpCode(size) {
	case asm.MemOpSize16:
		sz = 16
	case asm.MemOpSize32:
		sz = 32
	}
	b.FromBE(asm.R1, sz)
}

func cBPF2eBPF(b *asm.Block, pcap []pcap.BPFInstruction, linkType layers.LinkType) error {
	for i, cbpf := range pcap {
		code := uint8(cbpf.Code)

		op := bpfOp(code)
		class := bpfClass(code)
		src := bpfSrc(code)
		size := bpfSize(code)

		offset := int16(cbpf.Jt)<<8 | int16(cbpf.Jf)
		K := int32(cbpf.K)

		b.LabelNextInsn(fmt.Sprintf("orig_%d", i))

		switch class {
		case bpfClassMisc:
			return fmt.Errorf("misc class: %+v", cbpf)
		case bpfClassRet:
			// K is the return value and hit should be snap length, 0 otherwise.
			// https://github.com/the-tcpdump-group/libpcap/blob/aa4fd0d411239f5cc98f0ae14018d3ad91a5ee15/gencode.c#L822
			if K == 0 {
				b.Jump("miss")
			} else {
				b.Jump("hit")
			}
			continue
		case bpfClassLd:
			mode := bpfMode(code)
			switch mode {
			case bpfModeIND:
				b.Mov64(asm.R3 /* tmp */, asm.R7 /* pkt */) // Load pkt to tmp
				b.Add64(asm.R3 /* tmp */, asm.R2 /* X */)   // Move to pkt[X]
				if K > 0 {
					b.AddImm64(asm.R3, K) // Move to pkt[X+K]
				}
				b.JumpLE64(asm.R8, asm.R3, "exit")                                  // Check size
				b.Load(asm.R1 /* A */, asm.R3, asm.FieldOffset{}, asm.OpCode(size)) // A = pkt[X + K]
				if asm.OpCode(size) != asm.MemOpSize8 {
					fromBE(b, size)
				}
				continue
			case bpfModeABS:
				b.Load(asm.R1, asm.R7, asm.FieldOffset{Offset: int16(K), Field: ""}, asm.OpCode(size))
				if asm.OpCode(size) != asm.MemOpSize8 {
					fromBE(b, size)
				}
				continue
			case bpfModeLEN:
				b.Load32(asm.R1, asm.R6, asm.SkbuffOffsetLen)
				continue
			case bpfModeIMM:
				// eBPF has only 64bit imm instructions
				b.LoadImm64(asm.R1, int64(K))
				continue
			}
		case bpfClassLdx:
			if cbpf.Code == uint16(bpfClassLdx|bpfModeMSH|bpfSizeB) {
				switch {
				case linkType == layers.LinkTypeEthernet && K == 14:
					fallthrough
				case linkType == layers.LinkTypeIPv4 && K == 0:
					// We assume reading IP header size and we would assume that
					// the size is fixed without IP options.
					b.LoadImm64(asm.R2, 20)
				default:
					b.AddComment(fmt.Sprintf("Loadx 4 * (pkt[%d] & 0xf)", K))
					b.Mov64(asm.R3 /* tmp */, asm.R1 /* A */)                                               // Save A
					b.Load8(asm.R1 /* A */, asm.R7 /* pkt */, asm.FieldOffset{Offset: int16(K), Field: ""}) // Load pkt[K] to A
					b.AndImm64(asm.R1 /* A */, 0xf)                                                         // A = A & 0xf
					b.ShiftLImm64(asm.R1 /*A */, 2)                                                         // A << 2 resp. A *4
					b.Mov64(asm.R2 /* X */, asm.R1 /* A */)                                                 // Move A to X
					b.Mov64(asm.R1 /* A */, asm.R3 /* tmp */)                                               // Restore A from tmp
				}
				continue
			}
		case bpfClassJmp:

			var srcR asm.Reg
			if src == bpfX {
				srcR = asm.R2
			}

			if op == asm.JumpOpA {
				b.Jump(fmt.Sprintf("orig_%d", cbpf.Jt+1))
				continue
			}

			if cbpf.Jt != 0 && cbpf.Jf != 0 {
				neg := (code & 0xf) | uint8(jumpOpNegate[asm.OpCode(op)])

				b.AddComment("Jump with two targets")
				b.InstrWithOffsetFixup(asm.OpCode(code), asm.R1, srcR, fmt.Sprintf("orig_%d", i+int(cbpf.Jt+1)), K)
				b.InstrWithOffsetFixup(asm.OpCode(neg), asm.R1, srcR, fmt.Sprintf("orig_%d", i+int(cbpf.Jf+1)), K)

				continue
			}

			var target int

			if cbpf.Jf != 0 {
				b.AddComment("Jump with false target")
				op = uint8(jumpOpNegate[asm.OpCode(op)])
				target = i + int(cbpf.Jf) + 1
			} else {
				b.AddComment("Jump with true target")
				target = i + int(cbpf.Jt) + 1
			}
			code = (code & 0xf) | op

			b.InstrWithOffsetFixup(asm.OpCode(code), asm.R1, srcR, fmt.Sprintf("orig_%d", target), K)

			continue
		}

		dstR := asm.R1
		srcR := asm.R1
		if src == bpfX {
			srcR = asm.R2
		}

		b.Instr(asm.OpCode(code), dstR, srcR, offset, K, "")
	}
	return nil
}

var jumpOpNegate = map[asm.OpCode]asm.OpCode{
	asm.JumpOpEq:  asm.JumpOpNE,
	asm.JumpOpNE:  asm.JumpOpEq,
	asm.JumpOpGT:  asm.JumpOpLE,
	asm.JumpOpGE:  asm.JumpOpLT,
	asm.JumpOpSGT: asm.JumpOpSLE,
	asm.JumpOpSGE: asm.JumpOpSLT,
	asm.JumpOpLT:  asm.JumpOpGE,
	asm.JumpOpLE:  asm.JumpOpGT,
	asm.JumpOpSLT: asm.JumpOpSGE,
	asm.JumpOpSLE: asm.JumpOpSGT,
}

const (
	bpfClassLd   uint8 = 0x0
	bpfClassLdx  uint8 = 0x1
	bpfClassJmp  uint8 = 0x5
	bpfClassRet  uint8 = 0x6
	bpfClassMisc uint8 = 0x7
)

func bpfClass(code uint8) uint8 {
	return code & 0x07
}

const (
	bpfSizeW uint8 = 0x00 // 32-bit
	bpfSizeH uint8 = 0x08 // 16-bit
	bpfSizeB uint8 = 0x10 // 8-bit
)

var (
	_ = bpfSizeW
	_ = bpfSizeH
)

func bpfSize(code uint8) uint8 {
	return code & 0x18
}

const (
	bpfModeIMM uint8 = 0x00
	bpfModeABS uint8 = 0x20
	bpfModeIND uint8 = 0x40
	bpfModeMEM uint8 = 0x60
	bpfModeLEN uint8 = 0x80
	bpfModeMSH uint8 = 0xa0
)

var (
	_ = bpfModeIMM
	_ = bpfModeMEM
)

func bpfMode(code uint8) uint8 {
	return code & 0xe0
}

func bpfOp(code uint8) uint8 {
	return code & 0xf0
}

const (
	bpfK uint8 = 0
	bpfX uint8 = 0x8
)

var (
	_ = bpfK
)

func bpfSrc(code uint8) uint8 {
	return code & 0x08
}
