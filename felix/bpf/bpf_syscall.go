// Copyright (c) 2019-2022 Tigera, Inc. All rights reserved.
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
	"syscall"
	"time"
	"unsafe"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf/asm"
	"github.com/projectcalico/calico/felix/bpf/bpfutils"

	"golang.org/x/sys/unix"
)

// #include "bpf_syscall.h"
import "C"

func SyscallSupport() bool {
	return true
}

const defaultLogSize = 1024 * 1024
const maxLogSize = 128 * 1024 * 1024

func LoadBPFProgramFromInsns(insns asm.Insns, name, license string, progType uint32) (fd ProgFD, err error) {
	log.Debugf("LoadBPFProgramFromInsns(%v, %v, %v)", insns, license, progType)
	bpfutils.IncreaseLockedMemoryQuota()

	// Occasionally see retryable errors here, retry silently a few times before going into log-collection mode.
	backoff := 1 * time.Millisecond
	for retries := 10; retries > 0; retries-- {
		// By default, try to load the program with logging disabled.  This has two advantages: better performance
		// and the fact that the log cannot overflow.
		fd, err = tryLoadBPFProgramFromInsns(insns, name, license, 0, progType)
		if err == nil {
			log.WithField("fd", fd).Debug("Loaded program successfully")
			return fd, nil
		}
		log.WithError(err).Debug("Error loading BPF program; will retry.")
		time.Sleep(backoff)
		backoff *= 2
	}

	// Retry again, passing a log buffer to get the diagnostics from the kernel.
	log.WithError(err).Warn("Failed to load BPF program; collecting diagnostics...")
	var logSize uint = defaultLogSize
	for {
		fd, err2 := tryLoadBPFProgramFromInsns(insns, name, license, logSize, progType)
		if err2 == nil {
			// Unexpected but we'll take it.
			log.Warn("Retry succeeded.")
			return fd, nil
		}
		if err2 == unix.ENOSPC && logSize < maxLogSize {
			// Log buffer was too small.
			log.Warn("Diagnostics buffer was too small, trying again with a larger buffer.")
			logSize *= 2
			continue
		}
		if err != err2 {
			log.WithError(err2).Error("Retry failed with a different error.")
		}
		return 0, err
	}
}

func tryLoadBPFProgramFromInsns(insns asm.Insns, name, license string, logSize uint, progType uint32) (ProgFD, error) {
	log.Debugf("tryLoadBPFProgramFromInsns(..., %v, %v, %v)", license, logSize, progType)
	bpfAttr := C.bpf_attr_alloc()
	defer C.free(unsafe.Pointer(bpfAttr))

	cInsnBytes := C.CBytes(insns.AsBytes())
	defer C.free(cInsnBytes)
	cLicense := C.CString(license)
	defer C.free(unsafe.Pointer(cLicense))
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	var logBuf unsafe.Pointer
	var logLevel uint
	if logSize > 0 {
		logLevel = 1
		logBuf = C.malloc((C.size_t)(logSize))
		defer C.free(logBuf)
	}

	C.bpf_attr_setup_load_prog(bpfAttr, cName,
		(C.uint)(progType), C.uint(len(insns)), cInsnBytes, cLicense,
		(C.uint)(logLevel), (C.uint)(logSize), logBuf)
	fd, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_PROG_LOAD, uintptr(unsafe.Pointer(bpfAttr)), C.sizeof_union_bpf_attr)

	if errno != 0 && errno != unix.ENOSPC /* log buffer too small */ {
		goLog := strings.TrimSpace(C.GoString((*C.char)(logBuf)))
		log.WithError(errno).Debug("BPF_PROG_LOAD failed")
		if len(goLog) > 0 {
			for _, l := range strings.Split(goLog, "\n") {
				log.Error("BPF_PROG_LOAD failed, BPF Verifier output:    ", l)
			}
		} else if logSize > 0 {
			log.Error("BPF_PROG_LOAD failed, verifier log was empty.")
		}
	}

	if errno != 0 {
		return 0, errno
	}
	return ProgFD(fd), nil
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

	var errno syscall.Errno
	for attempts := 3; attempts > 0; attempts-- {
		C.bpf_attr_setup_prog_run(bpfAttr, C.uint(fd), C.uint(len(dataIn)), cDataIn, C.uint(dataOutBufSize), cDataOut, C.uint(repeat))
		_, _, errno = unix.Syscall(unix.SYS_BPF, unix.BPF_PROG_TEST_RUN, uintptr(unsafe.Pointer(bpfAttr)), C.sizeof_union_bpf_attr)
		if errno == unix.EINTR {
			// We hit this if a Go profiling timer pops while we're in the syscall.
			log.Debug("BPF_PROG_TEST_RUN hit EINTR")
			continue
		}
		break
	}
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
