// Copyright (c) 2019-2021 Tigera, Inc. All rights reserved.
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

//go:build !cgo

package bpf

import (
	"github.com/projectcalico/calico/felix/bpf/asm"
)

const MapIteratorNumKeys = 16

func SyscallSupport() bool {
	return false
}

func LoadBPFProgramFromInsns(insns asm.Insns, name, license string, progType uint32) (ProgFD, error) {
	panic("BPF syscall stub")
}

func LoadBPFProgramFromInsnsWithAttachType(insns asm.Insns, name, license string, progType, attachType uint32) (fd ProgFD, err error) {
	panic("BPF syscall stub")
}

func RunBPFProgram(fd ProgFD, dataIn []byte, repeat int) (pr ProgResult, err error) {
	panic("BPF syscall stub")
}

func PinBPFProgram(fd ProgFD, filename string) error {
	panic("BPF syscall stub")
}
