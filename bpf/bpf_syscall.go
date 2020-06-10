// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.
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

package bpf

import (
	"strings"
	"sync"
	"time"
	"unsafe"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/bpf/asm"

	"golang.org/x/sys/unix"
)

// #include <linux/bpf.h>
// #include <stdlib.h>
// #include <string.h>
//
// union bpf_attr *bpf_attr_alloc() {
//    union bpf_attr *attr = malloc(sizeof(union bpf_attr));
//    memset(attr, 0, sizeof(union bpf_attr));
//    return attr;
// }
//
// // bpf_attr_setup_obj_get sets up the bpf_attr union for use with BPF_OBJ_GET.
// // A C function makes this easier because unions aren't easy to access from Go.
// void bpf_attr_setup_obj_get(union bpf_attr *attr, char *path, __u32 flags) {
//    attr->pathname = (__u64)(unsigned long)path;
//    attr->bpf_fd = 0;
//    attr->file_flags = flags;
// }
//
// // bpf_attr_setup_obj_get_id sets up the bpf_attr union for use with BPF_XXX_GET_FD_BY_ID.
// // A C function makes this easier because unions aren't easy to access from Go.
// void bpf_attr_setup_obj_get_id(union bpf_attr *attr, __u32 id, __u32 flags) {
//    attr->map_id = id;
//    attr->open_flags = flags;
// }
//
// // bpf_attr_setup_obj_pin sets up the bpf_attr union for use with BPF_OBJ_PIN.
// // A C function makes this easier because unions aren't easy to access from Go.
// void bpf_attr_setup_obj_pin(union bpf_attr *attr, char *path, __u32 fd, __u32 flags) {
//    attr->pathname = (__u64)(unsigned long)path;
//    attr->bpf_fd = fd;
//    attr->file_flags = flags;
// }
//
// // bpf_attr_setup_map_elem sets up the bpf_attr union for use with BPF_MAP_GET|UPDATE
// // A C function makes this easier because unions aren't easy to access from Go.
// void bpf_attr_setup_map_elem(union bpf_attr *attr, __u32 map_fd, void *pointer_to_key, void *pointer_to_value, __u64 flags) {
//    attr->map_fd = map_fd;
//    attr->key = (__u64)(unsigned long)pointer_to_key;
//    attr->value = (__u64)(unsigned long)pointer_to_value;
//    attr->flags = flags;
// }
//
// // bpf_attr_setup_map_get_next_key sets up the bpf_attr union for use with BPF_MAP_GET_NEXT_KEY
// // A C function makes this easier because unions aren't easy to access from Go.
// void bpf_attr_setup_map_get_next_key(union bpf_attr *attr, __u32 map_fd, void *key, void *next_key, __u64 flags) {
//    attr->map_fd = map_fd;
//    attr->key = (__u64)(unsigned long)key;
//    attr->next_key = (__u64)(unsigned long)next_key;
//    attr->flags = flags;
// }
//
// // bpf_attr_setup_map_elem_for_delete sets up the bpf_attr union for use with BPF_MAP_DELETE_ELEM
// // A C function makes this easier because unions aren't easy to access from Go.
// void bpf_attr_setup_map_elem_for_delete(union bpf_attr *attr, __u32 map_fd, void *pointer_to_key) {
//    attr->map_fd = map_fd;
//    attr->key = (__u64)(unsigned long)pointer_to_key;
// }
//
// // bpf_attr_setup_load_prog sets up the bpf_attr union for use with BPF_PROG_LOAD.
// // A C function makes this easier because unions aren't easy to access from Go.
// void bpf_attr_setup_load_prog(union bpf_attr *attr, __u32 prog_type, __u32 insn_count, void *insns, char *license, __u32 log_size, void *log_buf) {
//    attr->prog_type = prog_type;
//    attr->insn_cnt = insn_count;
//    attr->insns = (__u64)(unsigned long)insns;
//    attr->license = (__u64)(unsigned long)license;
//    attr->log_level = 1;
//    attr->log_size = log_size;
//    attr->log_buf = (__u64)(unsigned long)log_buf;
//    attr->kern_version = 0;
//    if (log_size > 0) ((char *)log_buf)[0] = 0;
// }
//
// // bpf_attr_setup_prog_run sets up the bpf_attr union for use with BPF_PROG_TEST_RUN.
// // A C function makes this easier because unions aren't easy to access from Go.
// void bpf_attr_setup_prog_run(union bpf_attr *attr, __u32 prog_fd,
//                              __u32 data_size_in, void *data_in,
//                              __u32 data_size_out, void *data_out,
//                              __u32 repeat) {
//    attr->test.prog_fd = prog_fd;
//    attr->test.data_size_in = data_size_in;
//    attr->test.data_size_out = data_size_out;
//    attr->test.data_in = (__u64)(unsigned long)data_in;
//    attr->test.data_out = (__u64)(unsigned long)data_out;
//    attr->test.repeat = repeat;
// }
//
// // bpf_attr_setup_get_info sets up the bpf_attr union for use with BPF_OBJ_GET_INFO_BY_FD.
// // A C function makes this easier because unions aren't easy to access from Go.
// void bpf_attr_setup_get_info(union bpf_attr *attr, __u32 map_fd,
//                              __u32 info_size, void *info) {
//    attr->info.bpf_fd = map_fd;
//    attr->info.info_len = info_size;
//    attr->info.info = (__u64)(unsigned long)info;
// }
//
// __u32 bpf_attr_prog_run_retval(union bpf_attr *attr) {
//    return attr->test.retval;
// }
//
// __u32 bpf_attr_prog_run_data_out_size(union bpf_attr *attr) {
//    return attr->test.data_size_out;
// }
//
// __u32 bpf_attr_prog_run_duration(union bpf_attr *attr) {
//    return attr->test.duration;
// }
import "C"

func SyscallSupport() bool {
	return true
}

func GetMapFDByPin(filename string) (MapFD, error) {
	log.Debugf("GetMapFDByPin(%v)", filename)
	bpfAttr := C.bpf_attr_alloc()
	defer C.free(unsafe.Pointer(bpfAttr))

	cFilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cFilename))

	C.bpf_attr_setup_obj_get(bpfAttr, cFilename, 0)
	fd, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_OBJ_GET, uintptr(unsafe.Pointer(bpfAttr)), C.sizeof_union_bpf_attr)
	if errno != 0 {
		return 0, errno
	}

	return MapFD(fd), nil
}

func GetMapFDByID(mapID int) (MapFD, error) {
	log.Debugf("GetMapFDByID(%v)", mapID)
	bpfAttr := C.bpf_attr_alloc()
	defer C.free(unsafe.Pointer(bpfAttr))

	C.bpf_attr_setup_obj_get_id(bpfAttr, C.uint(mapID), 0)
	fd, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_MAP_GET_FD_BY_ID, uintptr(unsafe.Pointer(bpfAttr)), C.sizeof_union_bpf_attr)
	if errno != 0 {
		return 0, errno
	}

	return MapFD(fd), nil
}

func LoadBPFProgramFromInsns(insns asm.Insns, license string) (ProgFD, error) {
	log.Debugf("LoadBPFProgramFromInsns(%v, %v)", insns, license)
	increaseLockedMemoryQuota()
	bpfAttr := C.bpf_attr_alloc()
	defer C.free(unsafe.Pointer(bpfAttr))

	cInsnBytes := C.CBytes(insns.AsBytes())
	defer C.free(cInsnBytes)
	cLicense := C.CString(license)
	defer C.free(unsafe.Pointer(cLicense))
	const logSize = 1024 * 1024
	logBuf := C.malloc(logSize)
	defer C.free(logBuf)

	C.bpf_attr_setup_load_prog(bpfAttr, unix.BPF_PROG_TYPE_SCHED_CLS, C.uint(len(insns)), cInsnBytes, cLicense, logSize, logBuf)
	fd, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_PROG_LOAD, uintptr(unsafe.Pointer(bpfAttr)), C.sizeof_union_bpf_attr)

	if errno != 0 {
		goLog := strings.TrimSpace(C.GoString((*C.char)(logBuf)))
		log.WithError(errno).Error("BPF_PROG_LOAD failed")
		if len(goLog) > 0 {
			for _, l := range strings.Split(goLog, "\n") {
				log.Error("BPF Verifier:    ", l)
			}
		} else {
			log.Error("Verifier log was empty.")
		}
	}

	if errno != 0 {
		return 0, errno
	}
	return ProgFD(fd), nil
}

var memLockOnce sync.Once

func increaseLockedMemoryQuota() {
	memLockOnce.Do(func() {
		err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY})
		if err != nil {
			log.WithError(err).Error("Failed to increase RLIMIT_MEMLOCK, loading BPF programs may fail")
		}
	})
}

func RunBPFProgram(fd ProgFD, dataIn []byte, repeat int) (pr ProgResult, err error) {
	log.Debugf("RunBPFProgram(%v, ..., %v)", fd, repeat)
	bpfAttr := C.bpf_attr_alloc()
	defer C.free(unsafe.Pointer(bpfAttr))

	cDataIn := C.CBytes(dataIn)
	defer C.free(cDataIn)
	const dataOutBufSize = 4096
	cDataOut := C.malloc(dataOutBufSize)
	defer C.free(cDataOut)

	C.bpf_attr_setup_prog_run(bpfAttr, C.uint(fd), C.uint(len(dataIn)), cDataIn, C.uint(dataOutBufSize), cDataOut, C.uint(repeat))
	_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_PROG_TEST_RUN, uintptr(unsafe.Pointer(bpfAttr)), C.sizeof_union_bpf_attr)

	if errno != 0 {
		err = errno
		return
	}

	pr.RC = int32(C.bpf_attr_prog_run_retval(bpfAttr))
	dataOutSize := C.bpf_attr_prog_run_data_out_size(bpfAttr)
	pr.Duration = time.Duration(C.bpf_attr_prog_run_data_out_size(bpfAttr))
	pr.DataOut = C.GoBytes(cDataOut, C.int(dataOutSize))
	return
}

func PinBPFProgram(fd ProgFD, filename string) error {
	bpfAttr := C.bpf_attr_alloc()
	defer C.free(unsafe.Pointer(bpfAttr))

	cFilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cFilename))

	C.bpf_attr_setup_obj_pin(bpfAttr, cFilename, C.uint(fd), 0)
	_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_OBJ_PIN, uintptr(unsafe.Pointer(bpfAttr)), C.sizeof_union_bpf_attr)
	if errno != 0 {
		return errno
	}

	return nil
}

func UpdateMapEntry(mapFD MapFD, k, v []byte) error {
	log.Debugf("UpdateMapEntry(%v, %v, %v)", mapFD, k, v)

	err := checkMapIfDebug(mapFD, len(k), len(v))
	if err != nil {
		return err
	}

	bpfAttr := C.bpf_attr_alloc()
	defer C.free(unsafe.Pointer(bpfAttr))

	cK := C.CBytes(k)
	defer C.free(cK)
	cV := C.CBytes(v)
	defer C.free(cV)

	C.bpf_attr_setup_map_elem(bpfAttr, C.uint(mapFD), cK, cV, unix.BPF_ANY)

	_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_MAP_UPDATE_ELEM, uintptr(unsafe.Pointer(bpfAttr)), C.sizeof_union_bpf_attr)

	if errno != 0 {
		return errno
	}
	return nil
}

func GetMapEntry(mapFD MapFD, k []byte, valueSize int) ([]byte, error) {
	log.Debugf("GetMapEntry(%v, %v, %v)", mapFD, k, valueSize)

	err := checkMapIfDebug(mapFD, len(k), valueSize)
	if err != nil {
		return nil, err
	}

	bpfAttr := C.bpf_attr_alloc()
	defer C.free(unsafe.Pointer(bpfAttr))

	// Have to make C-heap copies here because passing these to the syscalls is done via pointers in an
	// intermediate struct.
	cK := C.CBytes(k)
	defer C.free(cK)
	cV := C.malloc(C.size_t(valueSize))
	defer C.free(cV)

	C.bpf_attr_setup_map_elem(bpfAttr, C.uint(mapFD), cK, cV, unix.BPF_ANY)

	_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_MAP_LOOKUP_ELEM, uintptr(unsafe.Pointer(bpfAttr)), C.sizeof_union_bpf_attr)

	v := C.GoBytes(cV, C.int(valueSize))

	if errno != 0 {
		return nil, errno
	}
	return v, nil
}

func checkMapIfDebug(mapFD MapFD, keySize, valueSize int) error {
	if log.GetLevel() >= log.DebugLevel {
		mapInfo, err := GetMapInfo(mapFD)
		if err != nil {
			log.WithError(err).Error("Failed to read map information")
			return err
		}
		log.WithField("mapInfo", mapInfo).Debug("Map metadata")
		if keySize != mapInfo.KeySize {
			log.WithField("mapInfo", mapInfo).WithField("keyLen", keySize).Panic("Incorrect key length")
		}
		if valueSize >= 0 && valueSize != mapInfo.ValueSize {
			log.WithField("mapInfo", mapInfo).WithField("valueLen", valueSize).Panic("Incorrect value length")
		}
	}
	return nil
}

func GetMapInfo(fd MapFD) (*MapInfo, error) {
	bpfAttr := C.bpf_attr_alloc()
	defer C.free(unsafe.Pointer(bpfAttr))
	var bpfMapInfo *C.struct_bpf_map_info = (*C.struct_bpf_map_info)(C.malloc(C.sizeof_struct_bpf_map_info))
	defer C.free(unsafe.Pointer(bpfMapInfo))

	C.bpf_attr_setup_get_info(bpfAttr, C.uint(fd), C.sizeof_struct_bpf_map_info, unsafe.Pointer(bpfMapInfo))
	_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_OBJ_GET_INFO_BY_FD, uintptr(unsafe.Pointer(bpfAttr)), C.sizeof_union_bpf_attr)

	if errno != 0 {
		return nil, errno
	}
	return &MapInfo{
		Type:      int(bpfMapInfo._type),
		KeySize:   int(bpfMapInfo.key_size),
		ValueSize: int(bpfMapInfo.value_size),
	}, nil
}

func DeleteMapEntry(mapFD MapFD, k []byte, valueSize int) error {
	log.Debugf("DeleteMapEntry(%v, %v, %v)", mapFD, k, valueSize)

	err := checkMapIfDebug(mapFD, len(k), valueSize)
	if err != nil {
		return err
	}

	bpfAttr := C.bpf_attr_alloc()
	defer C.free(unsafe.Pointer(bpfAttr))

	// Have to make C-heap copies here because passing these to the syscalls is done via pointers in an
	// intermediate struct.
	cK := C.CBytes(k)
	defer C.free(cK)

	C.bpf_attr_setup_map_elem_for_delete(bpfAttr, C.uint(mapFD), cK)

	_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_MAP_DELETE_ELEM, uintptr(unsafe.Pointer(bpfAttr)), C.sizeof_union_bpf_attr)

	if errno != 0 {
		return errno
	}
	return nil
}

// GetMapNextKey returns the next key for the given key if the current key exists.
// Otherwise it returns the first key. Order is implemention / map type
// dependent.
//
// Start iterating by passing a nil key.
func GetMapNextKey(mapFD MapFD, k []byte, keySize int) ([]byte, error) {
	log.Debugf("MapNextKey(%v, %v, %v)", mapFD, k, keySize)

	err := checkMapIfDebug(mapFD, keySize, -1)
	if err != nil {
		return nil, err
	}

	bpfAttr := C.bpf_attr_alloc()
	defer C.free(unsafe.Pointer(bpfAttr))

	var cK unsafe.Pointer

	// Have to make C-heap copies here because passing these to the syscalls is done via pointers in an
	// intermediate struct.
	//
	// it is valid to pass a nil key to start the iteration
	if k != nil {
		cK = C.CBytes(k)
		defer C.free(cK)
	}
	cV := C.malloc(C.size_t(keySize)) // value has the size of a key - it is the key!
	defer C.free(cV)

	C.bpf_attr_setup_map_get_next_key(bpfAttr, C.uint(mapFD), cK, cV, 0)

	_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_MAP_GET_NEXT_KEY,
		uintptr(unsafe.Pointer(bpfAttr)), C.sizeof_union_bpf_attr)

	v := C.GoBytes(cV, C.int(keySize))

	if errno != 0 {
		return nil, errno
	}

	return v, nil
}
