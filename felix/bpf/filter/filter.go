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

//go:build cgo

package filter

import (
	"encoding/binary"
	"fmt"

	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"

	"github.com/projectcalico/calico/felix/bpf/asm"
	"github.com/projectcalico/calico/felix/bpf/maps"
	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
)

var (
	skbCb0 = asm.FieldOffset{Offset: 12*4 + 0*4, Field: "skb->cb[0]"}
	skbCb1 = asm.FieldOffset{Offset: 12*4 + 1*4, Field: "skb->cb[1]"}
)

func New(epType tcdefs.EndpointType, maxData int, expression string, jumpMapFD, stateMapFD maps.FD) (asm.Insns, error) {
	linkType := layers.LinkTypeEthernet

	if epType == tcdefs.EpTypeL3Device {
		linkType = layers.LinkTypeIPv4
	}

	return newFilter(linkType, maxData, expression, jumpMapFD, stateMapFD, false)
}

func NewStandAlone(linkType layers.LinkType, maxData int, expression string, stateMapFD maps.FD) (asm.Insns, error) {
	return newFilter(linkType, maxData, expression, 0, stateMapFD, true)
}

func newFilter(
	linkType layers.LinkType,
	maxData int,
	expression string,
	jumpMapFD, stateMapFD maps.FD,
	standAlone bool) (asm.Insns, error) {

	b := asm.NewBlock(true)

	insns, err := pcap.CompileBPFFilter(linkType, maxData, expression)
	if err != nil {
		return nil, fmt.Errorf("pcap compile filter: %w", err)
	}

	programHeader(b, maxData, stateMapFD)

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

func programHeader(b *asm.Block, maxData int, stateMapFD maps.FD) {
	// Preamble to the policy program.
	b.LabelNextInsn("start")
	b.Mov64(asm.R6, asm.R1) // Save R1 (context) in R6.

	b.AddComment("Load packet bytes to stack buffer")
	// Load skb->len to determine how many bytes to load
	b.Load32(asm.R4, asm.R6, asm.SkbuffOffsetLen)

	// Calculate min(skb->len, maxData) and store in R4
	b.MovImm64(asm.R1, int32(maxData))
	b.JumpLE64(asm.R4, asm.R1, "use_skb_len")
	// If skb->len > maxData, use maxData
	b.Mov64(asm.R4, asm.R1)
	b.LabelNextInsn("use_skb_len")
	// R4 now contains min(skb->len, maxData)

	// Check that we have at least 1 byte to load (verifier requirement)
	b.JumpLTImm64(asm.R4, 1, "exit")

	// Save the actual length to load in R9 (callee-saved) before calling helper
	b.Mov64(asm.R9, asm.R4)

	b.AddComment("Get scratch buffer from state map")
	b.MovImm32(asm.R1, 0)                   // R1 = 0 -use state as scratch buffer, it is not used until after the filter
	b.StoreStack32(asm.R1, -4)              // store 0 at stack[-4] as a key to the state map
	b.Mov64(asm.R2, asm.R10)                // R2 = R10
	b.AddImm64(asm.R2, -4)                  // R2 = &stack[-4]
	b.LoadMapFD(asm.R1, uint32(stateMapFD)) // R1 = 0 (64-bit immediate)
	b.Call(asm.HelperMapLookupElem)         // Call helper
	// Check return value for NULL.
	b.JumpEqImm64(asm.R0, 0, "exit")
	// Set up R7 to point to the sracth buffer
	b.Mov64(asm.R7, asm.R0)

	// Prepare arguments for bpf_skb_load_bytes
	// R1 = skb (context)
	// R2 = offset (0 - start from beginning)
	// R3 = destination buffer
	b.Mov64(asm.R1, asm.R6) // ctx -> R1
	b.MovImm64(asm.R2, 0)   // offset = 0 (start from beginning)
	b.Mov64(asm.R3, asm.R7) // dest = scratch buffer
	b.Mov64(asm.R4, asm.R9) // restore length to load
	b.Call(asm.HelperSkbLoadBytes)

	// Check if bpf_skb_load_bytes succeeded (returns 0 on success)
	b.JumpNEImm64(asm.R0, 0, "exit")

	// Set up R8 to point to the end of actually loaded data (R7 + actual length)
	b.Mov64(asm.R8, asm.R7)
	b.Add64(asm.R8, asm.R9)

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
	b.Mov64(asm.R1, asm.R6)          // First arg is the context.
	b.LoadMapFD(asm.R2, uint32(fd))  // Second arg is the map.
	b.Load32(asm.R3, asm.R6, skbCb1) // Third arg is the index from skb->cb[1]).
	b.Call(asm.HelperTailCall)

	// If we do not have a program for logging, fall through to no logs.

	b.LabelNextInsn("miss")
	b.LabelNextInsn("exit")

	// Execute the tail call to no-log program
	b.Mov64(asm.R1, asm.R6)          // First arg is the context.
	b.LoadMapFD(asm.R2, uint32(fd))  // Second arg is the map.
	b.Load32(asm.R3, asm.R6, skbCb0) // Third arg is the index from skb->cb[0]).
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
