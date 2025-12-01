// Copyright (c) 2021-2025 Tigera, Inc. All rights reserved.
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
)

type Obj struct {
}

type Map struct {
}

type Link struct {
}

type Program struct {
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

func (o *Obj) SetProgramAutoload(progName string, autoload bool) {
	panic("LIBBPF syscall stub")
}

func (o *Obj) FirstMap() (*Map, error) {
	panic("LIBBPF syscall stub")
}

func (o *Obj) Filename() string {
	panic("LIBBPF syscall stub")
}

func (o *Obj) SetAttachType(progName string, attachType uint32) error {
	panic("LIBBPF syscall stub")
}

func (m *Map) NextMap() (*Map, error) {
	panic("LIBBPF syscall stub")
}

func (p *Program) NextProgram() (*Program, error) {
	panic("LIBBPF syscall stub")
}

func (o *Obj) FirstProgram() (*Program, error) {
	panic("LIBBPF syscall stub")
}

func (p *Program) Name() string {
	panic("LIBBPF syscall stub")
}

func QueryClassifier(ifindex, handle, pref int, ingress bool) (int, error) {
	panic("LIBBPF syscall stub")
}

func DetachClassifier(ifindex, handle, pref int, ingress bool) error {
	panic("LIBBPF syscall stub")
}

func (o *Obj) AttachClassifier(secName, ifName string, ingress bool, prio int, handle uint32) error {
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

func (o *Obj) AttachCGroupLegacy(_, _ string) error {
	panic("LIBBPF syscall stub")
}

func (o *Obj) UpdateLink(_, _ string) error {
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

func DetachLink(_ string) error {
	panic("LIBBPF syscall stub")
}

func (l *Link) Pin(_ string) error {
	panic("LIBBPF syscall stub")
}

func (l *Link) Update(obj *Obj, progName string) error {
	panic("LIBBPF syscall stub")
}

func (l *Link) Close() error {
	panic("LIBBPF syscall stub")
}

func OpenLink(path string) (*Link, error) {
	panic("LIBBPF syscall stub")
}

func (l *Link) Detach() error {
	panic("LIBBPF syscall stub")
}

func DetachCTLBProgramsLegacy(_ bool, _ string) error {
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
	GlobalsRPFOptionEnabled            uint32 = 16
	GlobalsRPFOptionStrict             uint32 = 32
	GlobalsNoDSRCidrs                  uint32 = 12345
	GlobalsLoUDPOnly                   uint32 = 12345
	GlobalsRedirectPeer                uint32 = 12345
	GlobalsFlowLogsEnabled             uint32 = 12345
	GlobalsNATOutgoingExcludeHosts     uint32 = 12345
	GlobalsSkipEgressRedirect          uint32 = 12345
	GlobalsIngressPacketRateConfigured uint32 = 12345
	GlobalsEgressPacketRateConfigured  uint32 = 12345
	AttachTypeTcxIngress               uint32 = 12345
	AttachTypeTcxEgress                uint32 = 12345
)

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

func MapUpdateBatch(fd int, k, v []byte, count int, flags uint64) (int, error) {
	panic("LIBBPF syscall stub")
}

func MapDeleteBatch(fd int, k []byte, count int, flags uint64) (int, error) {
	panic("LIBBPF syscall stub")
}

func (t *TcGlobalData) Set(m *Map) error {
	panic("LIBBPF syscall stub")
}

func (t *XDPGlobalData) Set(m *Map) error {
	panic("LIBBPF syscall stub")
}

func (t *CTCleanupGlobalData) Set(m *Map) error {
	panic("LIBBPF syscall stub")
}

func (t *CTLBGlobalData) Set(m *Map) error {
	panic("LIBBPF syscall stub")
}

func ProgQueryTcx(ifindex int, ingress bool) ([64]uint32, [64]uint32, uint32, error) {
	panic("LIBBPF syscall stub")
}

func ProgName(id uint32) (string, error) {
	panic("LIBBPF syscall stub")
}

func (o *Obj) AttachTCX(secName, ifName string) (*Link, error) {
	panic("LIBBPF syscall stub")
}

func OpenObjectWithLogBuffer(filename string, buf []byte) (*Obj, error) {
	panic("LIBBPF syscall stub")
}

func CreateBPFMap(mapType string, keySize int, valueSize int, maxEntries int, flags int, name string) (int, error) {
	panic("LIBBPF syscall stub")
}
