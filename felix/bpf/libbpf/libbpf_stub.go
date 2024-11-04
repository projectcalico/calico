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
	"runtime"
	"time"
)

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

func (m *Map) ValueSize() int {
	panic("LIBBPF syscall stub")
}

func (m *Map) KeySize() int {
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

func QueryClassifier(ifindex, handle, pref int, ingress bool) (int, error) {
	panic("LIBBPF syscall stub")
}

func DetachClassifier(ifindex, handle, pref int, ingress bool) error {
	panic("LIBBPF syscall stub")
}

func (o *Obj) AttachClassifier(secName, ifName string, ingress bool, prio int) (int, int, int, error) {
	panic("LIBBPF syscall stub")
}

func (o *Obj) AttachXDP(ifName, progName string, oldFD int, mode uint) (int, error) {
	panic("LIBBPF syscall stub")
}

func DetachXDP(ifName string, mode uint) error {
	panic("LIBBPF syscall stub")
}

func GetXDPProgramID(ifName string) (int, error) {
	panic("LIBBPF syscall stub")
}

func (o *Obj) AttachCGroup(_, _ string) (*Link, error) {
	panic("LIBBPF syscall stub")
}

func (o *Obj) PinPrograms(_ string) error {
	panic("LIBBPF syscall stub")
}

func (o *Obj) UnpinPrograms(_ string) error {
	panic("LIBBPF syscall stub")
}

func (o *Obj) PinMaps(_ string) error {
	panic("LIBBPF syscall stub")
}

func (o *Obj) ProgramFD(_ string) (int, error) {
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
	GlobalsIPv6Enabled      uint32 = 1
	GlobalsRPFOptionEnabled uint32 = 16
	GlobalsRPFOptionStrict  uint32 = 32
	GlobalsNoDSRCidrs       uint32 = 12345
	GlobalsLoUDPOnly        uint32 = 12345
	GlobalsRedirectPeer     uint32 = 12345
)

func TcSetGlobals(_ *Map, globalData *TcGlobalData) error {
	panic("LIBBPF syscall stub")
}

func CTLBSetGlobals(_ *Map, _ time.Duration, _ bool) error {
	panic("LIBBPF syscall stub")
}

func CTCleanupSetGlobals(
	m *Map,
	CreationGracePeriod time.Duration,
	TCPPreEstablished time.Duration,
	TCPEstablished time.Duration,
	TCPFinsSeen time.Duration,
	TCPResetSeen time.Duration,
	UDPLastSeen time.Duration,
	GenericIPLastSeen time.Duration,
	ICMPLastSeen time.Duration,
) error {
	panic("LIBBPF syscall stub")
}

func XDPSetGlobals(_ *Map, _ *XDPGlobalData) error {
	panic("LIBBPF syscall stub")
}

func (m *Map) SetSize(size int) error {
	panic("LIBBPF syscall stub")
}

func NumPossibleCPUs() (int, error) {
	return runtime.NumCPU(), nil
}

func ObjPin(_ int, _ string) error {
	panic("LIBBPF syscall stub")
}

func ObjGet(_ string) (int, error) {
	panic("LIBBPF syscall stub")
}
