// Copyright (c) 2023 Tigera, Inc. All rights reserved.
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

package maps

func NewIterator(mapFD FD, keySize, valueSize, maxEntries int, batchLookupSupported bool) (*Iterator, error) {
	panic("BPF syscall stub")
}

func GetMapFDByPin(filename string) (FD, error) {
	panic("BPF syscall stub")
}

func GetMapFDByID(mapID int) (FD, error) {
	panic("BPF syscall stub")
}

func UpdateMapEntry(mapFD FD, k, v []byte) error {
	panic("BPF syscall stub")
}

func UpdateMapEntryWithFlags(mapFD FD, k, v []byte, flags int) error {
	panic("BPF syscall stub")
}

func GetMapEntry(mapFD FD, k []byte, valueSize int) ([]byte, error) {
	panic("BPF syscall stub")
}

func GetMapInfo(fd FD) (*MapInfo, error) {
	panic("BPF syscall stub")
}

func DeleteMapEntry(mapFD FD, k []byte) error {
	panic("BPF syscall stub")
}

func DeleteMapEntryIfExists(mapFD FD, k []byte) error {
	panic("BPF syscall stub")
}

func GetMapNextKey(mapFD FD, k []byte, keySize int) ([]byte, error) {
	panic("BPF syscall stub")
}

func NewMapIterator(mapFD FD, keySize, valueSize, maxEntries int) (*MapIterator, error) {
	panic("BPF syscall stub")
}

type MapIterator struct {
}

func (m *Iterator) Next() (k, v []byte, err error) {
	return
}

func (m *Iterator) Close() error {
	return nil
}

func createMap(name string, mapType, keySize, valueSize, maxEntries, flags uint32) (FD, error) {
	panic("BPF syscall stub")
}

func batchLookup(mapFD FD, keySize, valueSize int) error {
	panic("BPF syscall stub")
}
