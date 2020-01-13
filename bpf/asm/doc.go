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

// Package asm contains a basic eBPF bytecode assembler.  So far, the instructions that are useful in
// our BPF programs have been added but adding additional instructions is straightforward following
// the pattern.
//
// Most BPF instructions are 8 bytes (the exception being 64-bit immediate loads).  All 8-byte
// instructions have the same format and the vast majority are general purpose instructions (i.e.
// they operate on the designated src/dst register only and don't clobber anything else).  We only
// use the general purpose instructions at present.
//
// The instruction format is represented by the Insn type.  It consists of a 1-byte opcode,
// 4 bits each for src and dst registers, a 16-bit offset (used for loads, stores and jumps)
// and a 32-bit signed immediate.
//
// The BPF ALU supports both 32-bit and 64-bit arithmetic and jump instructions.  Since only 2 registers
// can be named in an instruction, ALU operations use the dst register as one of their inputs
// as well as the output.
//
// BPF supports calling certain designated helper functions, which are exported by the kernel.
// To call a helper function, place its arguments in R1-R5 and then execute the Call instruction
// with one of the HelperXXX constants.
package asm
