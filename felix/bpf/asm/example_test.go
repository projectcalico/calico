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

package asm_test

import (
	"fmt"

	"github.com/projectcalico/calico/felix/bpf"
	. "github.com/projectcalico/calico/felix/bpf/asm"
)

func ExampleBlock() {
	b := NewBlock(false)
	b.MovImm64(R1, 10)         // R1 = 10
	b.MovImm64(R2, 20)         // R2 = 20
	b.JumpLE64(1, 2, "target") // if R1 < R2 jump to label "target"

	b.MovImm64(R0, 1) // Instruction will be jumped over.
	b.Jump("exit")

	b.LabelNextInsn("target") // Label the next instruction as "target"
	b.MovImm64(R0, 2)         //

	b.LabelNextInsn("exit") // Label the next instruction as "exit"
	b.Exit()                // Return from the BPF program (result is in R0).

	// Assemble the program; this resolves the jumps and returns the bytecode.
	insns, err := b.Assemble()
	if err != nil {
		panic(err)
	}

	fmt.Println("Instructions:")
	for _, i := range insns.Instructions {
		fmt.Println(i)
	}

	// Output:
	// Instructions:
	// MovImm64 dst=R1 src=R0 off=0 imm=0x0000000a/10
	// MovImm64 dst=R2 src=R0 off=0 imm=0x00000014/20
	// JumpLE64 dst=R1 src=R2 off=2 imm=0x00000000/0
	// MovImm64 dst=R0 src=R0 off=0 imm=0x00000001/1
	// JumpA dst=R0 src=R0 off=1 imm=0x00000000/0
	// MovImm64 dst=R0 src=R0 off=0 imm=0x00000002/2
	// Exit dst=R0 src=R0 off=0 imm=0x00000000/0
}

func ExampleBlock_Call() {
	// Made up map file descriptor, this needs to be loaded form the kernel.
	var mapFD bpf.MapFD = 5

	b := NewBlock(false)

	// Store 64-bit 0 on the stack at offset -8 (stack grows down).
	b.MovImm64(R1, 0)
	b.StoreStack64(R1, -8)

	// Get the address of the value we put on the stack in R2.
	b.Mov64(R2, R10)
	b.AddImm64(R2, -8)

	// Special instruction to load a map file descriptor (obtained from bpf.Map.MapFD())
	b.LoadMapFD(R1, uint32(mapFD))

	// Call the helper, this clobbers R1-R5 and returns the result in R0.
	b.Call(HelperMapLookupElem)

	// Check the return value (in R0) for NULL.
	b.JumpEqImm64(R0, 0, "miss")

	// If we fall through, the value wasn't NULL, return 1.
	b.MovImm64(R0, 1)
	b.Exit()

	b.LabelNextInsn("miss")
	// If we get here, the value was NULL, return 2.
	b.MovImm64(R0, 2)
	b.Exit()

	// Assemble the program; this resolves the jumps and returns the bytecode.
	insns, err := b.Assemble()
	if err != nil {
		panic(err)
	}

	fmt.Println("Instructions:")
	for _, i := range insns.Instructions {
		fmt.Println(i)
	}

	// Output:
	// Instructions:
	// MovImm64 dst=R1 src=R0 off=0 imm=0x00000000/0
	// StoreReg64 dst=R10 src=R1 off=-8 imm=0x00000000/0
	// Mov64 dst=R2 src=R10 off=0 imm=0x00000000/0
	// AddImm64 dst=R2 src=R0 off=0 imm=0xfffffff8/-8
	// LoadImm64 dst=R1 src=R1 off=0 imm=0x00000005/5
	// LoadImm64Pt2 dst=R0 src=R0 off=0 imm=0x00000000/0
	// Call dst=R0 src=R0 off=0 imm=0x00000001/1
	// JumpEqImm64 dst=R0 src=R0 off=2 imm=0x00000000/0
	// MovImm64 dst=R0 src=R0 off=0 imm=0x00000001/1
	// Exit dst=R0 src=R0 off=0 imm=0x00000000/0
	// MovImm64 dst=R0 src=R0 off=0 imm=0x00000002/2
	// Exit dst=R0 src=R0 off=0 imm=0x00000000/0
}
