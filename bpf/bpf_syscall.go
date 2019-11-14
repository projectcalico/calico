// Copyright (c) 2019 Tigera, Inc. All rights reserved.
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
	"unsafe"

	"golang.org/x/sys/unix"
)

// #include <linux/bpf.h>
// #include <stdlib.h>
//
// // bpf_attr_setup_obj_get sets up the bpf_attr union for use with BPF_OBJ_GET.
// // A C function makes this easier because unions aren't easy to access from Go.
// void bpf_attr_setup_obj_get(union bpf_attr *attr, char *path, __u32 flags) {
//    attr->pathname = (__u64)(unsigned long)path;
//    attr->bpf_fd = 0;
//    attr->file_flags = flags;
// }
//
// // bpf_attr_setup_update_elem sets up the bpf_attr union for use with BPF_MAP_UPDATE_ELEM.
// // A C function makes this easier because unions aren't easy to access from Go.
// void bpf_attr_setup_update_elem(union bpf_attr *attr, __u32 map_fd, void *pointer_to_key, void *pointer_to_value, __u64 flags) {
//    attr->map_fd = map_fd;
//    attr->key = (__u64)(unsigned long)pointer_to_key;
//    attr->value = (__u64)(unsigned long)pointer_to_value;
//    attr->flags = flags;
// }
//
// // bpf_attr_setup_get_elem sets up the bpf_attr union for use with BPF_MAP_GET_ELEM.
// // A C function makes this easier because unions aren't easy to access from Go.
// void bpf_attr_setup_get_elem(union bpf_attr *attr, __u32 map_fd, void *pointer_to_key, void *pointer_to_value, __u64 flags) {
//    attr->map_fd = map_fd;
//    attr->key = (__u64)(unsigned long)pointer_to_key;
//    attr->value = (__u64)(unsigned long)pointer_to_value;
//    attr->flags = flags;
// }
//
// // bpf_attr_setup_delete_elem sets up the bpf_attr union for use with BPF_MAP_DELETE_ELEM.
// // A C function makes this easier because unions aren't easy to access from Go.
// void bpf_attr_setup_delete_elem(union bpf_attr *attr, __u32 map_fd, void *pointer_to_key) {
//    attr->map_fd = map_fd;
//    attr->key = (__u64)(unsigned long)pointer_to_key;
// }
import "C"

type MapFD uint32

func (f MapFD) Close() error {
	return unix.Close(int(f))
}

func GetPinnedMapFD(filename string) (MapFD, error) {
	var bpfAttr C.union_bpf_attr

	cFilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cFilename))

	C.bpf_attr_setup_obj_get(&bpfAttr, cFilename, 0)
	fd, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_OBJ_GET, uintptr(unsafe.Pointer(&bpfAttr)), C.sizeof_union_bpf_attr)
	if errno != 0 {
		return 0, errno
	}

	return MapFD(fd), nil
}

func UpdateMapEntry(mapFD MapFD, k, v []byte) error {
	var bpfAttr C.union_bpf_attr

	cK := C.CBytes(k)
	cV := C.CBytes(v)

	C.bpf_attr_setup_update_elem(&bpfAttr, C.uint(mapFD), cK, cV, unix.BPF_ANY)

	_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_MAP_UPDATE_ELEM, uintptr(unsafe.Pointer(&bpfAttr)), C.sizeof_union_bpf_attr)

	C.free(cK)
	C.free(cV)

	if errno != 0 {
		return errno
	}
	return nil
}

func GetMapEntry(mapFD MapFD, k []byte, valueSize int) ([]byte, error) {
	var bpfAttr C.union_bpf_attr

	// Have to make C-heap copies here because passing these to the syscalls is done via pointers in an
	// intermediate struct.
	cK := C.CBytes(k)
	cV := C.malloc(C.size_t(valueSize))

	C.bpf_attr_setup_update_elem(&bpfAttr, C.uint(mapFD), cK, cV, unix.BPF_ANY)

	_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_MAP_LOOKUP_ELEM, uintptr(unsafe.Pointer(&bpfAttr)), C.sizeof_union_bpf_attr)

	v := C.GoBytes(cV, C.int(valueSize))

	C.free(cK)
	C.free(cV)

	if errno != 0 {
		return nil, errno
	}
	return v, nil
}

func IsNotExists(err error) bool {
	return err == unix.ENOENT
}

func DeleteMapEntry(mapFD MapFD, k []byte) error {
	var bpfAttr C.union_bpf_attr

	cK := C.CBytes(k)

	C.bpf_attr_setup_delete_elem(&bpfAttr, C.uint(mapFD), cK)

	r, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_MAP_DELETE_ELEM, uintptr(unsafe.Pointer(&bpfAttr)), C.sizeof_union_bpf_attr)

	C.free(cK)

	if r != 0 {
		return errno
	}
	return nil
}
