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

//go:build !windows

package maps

import (
	"runtime"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// #include "syscall.h"
import "C"

func GetMapFDByPin(filename string) (FD, error) {
	log.Debugf("GetMapFDByPin(%v)", filename)
	bpfAttr := C.bpf_maps_attr_alloc()
	defer C.free(unsafe.Pointer(bpfAttr))

	cFilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cFilename))

	C.bpf_maps_attr_setup_obj_get(bpfAttr, cFilename, 0)
	fd, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_OBJ_GET, uintptr(unsafe.Pointer(bpfAttr)), C.sizeof_union_bpf_attr)
	if errno != 0 {
		return 0, errno
	}

	return FD(fd), nil
}

func GetMapFDByID(mapID int) (FD, error) {
	log.Debugf("GetMapFDByID(%v)", mapID)
	bpfAttr := C.bpf_maps_attr_alloc()
	defer C.free(unsafe.Pointer(bpfAttr))

	C.bpf_maps_attr_setup_obj_get_id(bpfAttr, C.uint(mapID), 0)
	fd, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_MAP_GET_FD_BY_ID, uintptr(unsafe.Pointer(bpfAttr)), C.sizeof_union_bpf_attr)
	if errno != 0 {
		return 0, errno
	}

	return FD(fd), nil
}

func UpdateMapEntry(mapFD FD, k, v []byte) error {
	return UpdateMapEntryWithFlags(mapFD, k, v, unix.BPF_ANY)
}

func UpdateMapEntryWithFlags(mapFD FD, k, v []byte, flags int) error {
	log.Debugf("UpdateMapEntry(%v, %v, %v)", mapFD, k, v)

	err := checkMapIfDebug(mapFD, len(k), len(v))
	if err != nil {
		return err
	}

	bpfAttr := C.bpf_maps_attr_alloc()
	defer C.free(unsafe.Pointer(bpfAttr))

	cK := C.CBytes(k)
	defer C.free(cK)
	cV := C.CBytes(v)
	defer C.free(cV)

	C.bpf_maps_attr_setup_map_elem(bpfAttr, C.uint(mapFD), cK, cV, C.ulonglong(flags))

	_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_MAP_UPDATE_ELEM, uintptr(unsafe.Pointer(bpfAttr)), C.sizeof_union_bpf_attr)

	if errno != 0 {
		return errno
	}
	return nil
}

func GetMapEntry(mapFD FD, k []byte, valueSize int) ([]byte, error) {
	log.Debugf("GetMapEntry(%v, %v, %v)", mapFD, k, valueSize)

	err := checkMapIfDebug(mapFD, len(k), valueSize)
	if err != nil {
		return nil, err
	}

	val := make([]byte, valueSize)

	errno := C.bpf_maps_map_call(unix.BPF_MAP_LOOKUP_ELEM, C.uint(mapFD),
		unsafe.Pointer(&k[0]), unsafe.Pointer(&val[0]), 0)
	if errno != 0 {
		return nil, unix.Errno(errno)
	}

	return val, nil
}

func checkMapIfDebug(mapFD FD, keySize, valueSize int) error {
	if log.GetLevel() < log.DebugLevel {
		return nil
	}
	mapInfo, err := GetMapInfo(mapFD)
	if err != nil {
		log.WithError(err).Error("Failed to read map information")
		return err
	}
	log.WithField("fd", mapFD).WithField("mapInfo", mapInfo).Debug("Map metadata")
	if keySize != mapInfo.KeySize {
		log.WithField("mapInfo", mapInfo).WithField("keyLen", keySize).Panic("Incorrect key length")
	}
	switch mapInfo.Type {
	case unix.BPF_MAP_TYPE_PERCPU_HASH, unix.BPF_MAP_TYPE_PERCPU_ARRAY, unix.BPF_MAP_TYPE_LRU_PERCPU_HASH, unix.BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE:
		// The actual size of per cpu maps is equal to the value size * number of cpu
		ncpus := NumPossibleCPUs()
		if valueSize >= 0 && valueSize != mapInfo.ValueSize*ncpus {
			log.WithField("mapInfo", mapInfo).WithField("valueLen", valueSize).Panic("Incorrect value length for per-CPU map")
		}
	default:
		if valueSize >= 0 && valueSize != mapInfo.ValueSize {
			log.WithField("mapInfo", mapInfo).WithField("valueLen", valueSize).Panic("Incorrect value length")
		}
	}
	return nil
}

func GetMapInfo(fd FD) (*MapInfo, error) {
	bpfAttr := C.bpf_maps_attr_alloc()
	defer C.free(unsafe.Pointer(bpfAttr))
	var bpfMapInfo *C.struct_bpf_map_info = (*C.struct_bpf_map_info)(C.malloc(C.sizeof_struct_bpf_map_info))
	defer C.free(unsafe.Pointer(bpfMapInfo))

	C.bpf_maps_attr_setup_get_info(bpfAttr, C.uint(fd), C.sizeof_struct_bpf_map_info, unsafe.Pointer(bpfMapInfo))
	_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_OBJ_GET_INFO_BY_FD, uintptr(unsafe.Pointer(bpfAttr)), C.sizeof_union_bpf_attr)

	if errno != 0 {
		return nil, errno
	}
	return &MapInfo{
		Type:       int(bpfMapInfo._type),
		KeySize:    int(bpfMapInfo.key_size),
		ValueSize:  int(bpfMapInfo.value_size),
		MaxEntries: int(bpfMapInfo.max_entries),
	}, nil
}

func DeleteMapEntry(mapFD FD, k []byte) error {
	log.Debugf("DeleteMapEntry(%v, %v)", mapFD, k)

	err := checkMapIfDebug(mapFD, len(k), -1)
	if err != nil {
		return err
	}

	errno := C.bpf_maps_map_call(unix.BPF_MAP_DELETE_ELEM, C.uint(mapFD),
		unsafe.Pointer(&k[0]), unsafe.Pointer(nil), 0)
	if errno != 0 {
		return unix.Errno(errno)
	}

	return nil
}

func DeleteMapEntryIfExists(mapFD FD, k []byte) error {
	err := DeleteMapEntry(mapFD, k)
	if err == unix.ENOENT {
		// Delete failed because entry did not exist.
		err = nil
	}
	return err
}

// Batch size established by trial and error; 8-32 seemed to be the sweet spot for the conntrack map.
const IteratorNumKeys = 16

// align64 rounds up the given size to the nearest 8-bytes.
func align64(size int) int {
	if size%8 == 0 {
		return size
	}
	return size + (8 - (size % 8))
}

func NewIterator(mapFD FD, keySize, valueSize, maxEntries int) (*Iterator, error) {
	err := checkMapIfDebug(mapFD, keySize, valueSize)
	if err != nil {
		return nil, err
	}

	keyStride := align64(keySize)
	valueStride := align64(valueSize)

	keysBufSize := (C.size_t)(keyStride * IteratorNumKeys)
	valueBufSize := (C.size_t)(valueStride * IteratorNumKeys)

	m := &Iterator{
		mapFD:       mapFD,
		maxEntries:  maxEntries,
		keySize:     keySize,
		valueSize:   valueSize,
		keyStride:   keyStride,
		valueStride: valueStride,
		keys:        C.malloc(keysBufSize),
		values:      C.malloc(valueBufSize),
	}

	C.memset(m.keys, 0, (C.size_t)(keysBufSize))
	C.memset(m.values, 0, (C.size_t)(valueBufSize))

	// Make sure the C buffers are cleaned up.
	runtime.SetFinalizer(m, func(m *Iterator) {
		err := m.Close()
		if err != nil {
			log.WithError(err).Panic("Unexpected error from Iterator.Close().")
		}
	})

	return m, nil
}

// Next gets the next key/value pair from the iteration.  The key and value []byte slices returned point to the
// Iterator's internal buffers (which are allocated on the C heap); they should not be retained or modified.
// Returns ErrIterationFinished at the end of the iteration or ErrVisitedTooManyKeys if it visits considerably more
// keys than the maximum size of the map.
func (m *Iterator) Next() (k, v []byte, err error) {
	if m.numEntriesLoaded == m.entryIdx {
		// Need to load a new batch of KVs from the kernel.
		var count C.int
		rc := C.bpf_maps_map_load_multi(C.uint(m.mapFD), m.keyBeforeNextBatch, IteratorNumKeys,
			C.int(m.keyStride), m.keys, C.int(m.valueStride), m.values)
		if rc < 0 {
			err = unix.Errno(-rc)
			return
		}
		count = rc
		if count == 0 {
			// No error but no keys either.  We're done.
			err = ErrIterationFinished
			return
		}

		m.numEntriesLoaded = int(count)
		m.entryIdx = 0
		if m.keyBeforeNextBatch == nil {
			m.keyBeforeNextBatch = C.malloc((C.size_t)(m.keySize))
		}
		C.memcpy(m.keyBeforeNextBatch,
			unsafe.Pointer(uintptr(m.keys)+uintptr(m.keyStride*(m.numEntriesLoaded-1))), (C.size_t)(m.keySize))
	}

	currentKeyPtr := (*byte)(unsafe.Pointer(uintptr(m.keys) + uintptr(m.keyStride*(m.entryIdx))))
	currentValPtr := (*byte)(unsafe.Pointer(uintptr(m.values) + uintptr(m.valueStride*(m.entryIdx))))

	k = unsafe.Slice(currentKeyPtr, m.keySize)
	v = unsafe.Slice(currentValPtr, m.valueSize)

	m.entryIdx++
	m.numEntriesVisited++

	if m.numEntriesVisited > m.maxEntries*10 {
		// Either a bug or entries are being created 10x faster than we're iterating through them?
		err = ErrVisitedTooManyKeys
		return
	}

	return
}

func (m *Iterator) Close() error {
	C.free(m.keyBeforeNextBatch)
	m.keyBeforeNextBatch = nil
	C.free(m.keys)
	m.keys = nil
	C.free(m.values)
	m.values = nil

	// Don't need the finalizer any more.
	runtime.SetFinalizer(m, nil)

	return nil
}
