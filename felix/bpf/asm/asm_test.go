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
	"testing"

	. "github.com/onsi/gomega"
)

func TestBlock_Mov64(t *testing.T) {
	RegisterTestingT(t)
	b := NewBlock()
	b.Mov64(6, 1)
	Expect(b.insns.Instructions).To(Equal([]Insn{{0xbf, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}))
}

func TestBlock_MovImm64(t *testing.T) {
	RegisterTestingT(t)
	b := NewBlock()
	b.MovImm64(1, 0x1eadbeef)
	Expect(b.insns.Instructions).To(Equal([]Insn{{0xb7, 0x01, 0, 0, 0xef, 0xbe, 0xad, 0x1e}}))
}

func TestBlock_JumpLE64(t *testing.T) {
	RegisterTestingT(t)
	b := NewBlock()
	b.JumpLE64(1, 2, "foo")
	b.MovImm64(1, 0x1eadbeef)
	b.MovImm64(1, 0x2eadbeef)
	b.LabelNextInsn("foo")
	b.MovImm64(1, 0x3eadbeef)
	insns, err := b.Assemble()
	Expect(err).NotTo(HaveOccurred())

	Expect(insns.Instructions).To(Equal([]Insn{
		{0xbd, 0x21, 0x02, 0x00, 0, 0, 0, 0},
		{0xb7, 0x01, 0, 0, 0xef, 0xbe, 0xad, 0x1e},
		{0xb7, 0x01, 0, 0, 0xef, 0xbe, 0xad, 0x2e},
		{0xb7, 0x01, 0, 0, 0xef, 0xbe, 0xad, 0x3e},
	}))
}

func TestBlock_Mainline(t *testing.T) {
	RegisterTestingT(t)
	b := NewBlock()

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

	Expect(insns.Instructions).To(Equal([]Insn{
		{0xbf, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		{0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		{0x63, 0x1a, 0xe4, 0xff, 0x00, 0x00, 0x00, 0x00},
		{0xbf, 0xa2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		{0x07, 0x02, 0x00, 0x00, 0xe4, 0xff, 0xff, 0xff},
		{0x18, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // 64-bit immediate
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		{0x85, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00},
		{0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		{0xb7, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00},
		{0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	}))
}
