// Copyright (c) 2021-2022 Tigera, Inc. All rights reserved.
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

package libbpf

import (
	"time"
)

const MapTypeProgrArray = 3

type Obj struct {
}

type Map struct {
}

type Link struct {
}

func (m *Map) Name() string {
	panic("LIBBPF syscall stub")
}

func (m *Map) Type() int {
	panic("LIBBPF syscall stub")
}

func (m *Map) SetPinPath(path string) error {
	panic("LIBBPF syscall stub")
}

func OpenObject(filename string) (*Obj, error) {
	panic("LIBBPF syscall stub")
}

func (o *Obj) Load() error {
	panic("LIBBPF syscall stub")
}

func (o *Obj) FirstMap() (*Map, error) {
	panic("LIBBPF syscall stub")
}

func (m *Map) NextMap() (*Map, error) {
	panic("LIBBPF syscall stub")
}

func (o *Obj) AttachClassifier(secName, ifName, hook string) (int, error) {
	panic("LIBBPF syscall stub")
}

func (o *Obj) AttachCGroup(_, _ string) (*Link, error) {
	panic("LIBBPF syscall stub")
}

func CreateQDisc(ifName string) error {
	panic("LIBBPF syscall stub")
}

func RemoveQDisc(ifName string) error {
	panic("LIBBPF syscall stub")
}

func (o *Obj) UpdateJumpMap(mapName, progName string, mapIndex int) error {
	panic("LIBBPF syscall stub")
}

func (o *Obj) Close() error {
	panic("LIBBPF syscall stub")
}

func (m *Map) IsMapInternal() bool {
	panic("LIBBPF syscall stub")
}

const (
	GlobalsIPv6Enabled        uint32 = 1
	GlobalsIPIPNoOuterHeaders uint32 = 2
)

func TcSetGlobals(_ *Map, _, _, _ uint32, _, _, _, _ uint16, _ uint32) error {
	panic("LIBBPF syscall stub")
}

func CTLBSetGlobals(_ *Map, _ time.Duration) error {
	panic("LIBBPF syscall stub")
}

func (m *Map) SetMapSize(size uint32) error {
	panic("LIBBPF syscall stub")
}
