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
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/bpf/asm"
	"github.com/projectcalico/calico/felix/bpf/utils"
)

// #cgo CFLAGS: -I${SRCDIR}/../bpf-gpl/libbpf/src -I${SRCDIR}/../bpf-gpl/libbpf/include/uapi -I${SRCDIR}/../bpf-gpl -Werror
// #include "bpf_syscall.h"
import "C"

func SyscallSupport() bool {
	return true
}

const defaultLogSize = 1024 * 1024
const maxLogSize = 128 * 1024 * 1024

func LoadBPFProgramFromInsnsWithAttachType(insns asm.Insns, name, license string, progType, attachType uint32) (fd ProgFD, err error) {
	return loadBPFProgramFromInsns(insns, name, license, progType, attachType)
}

func LoadBPFProgramFromInsns(insns asm.Insns, name, license string, progType uint32) (fd ProgFD, err error) {
	return loadBPFProgramFromInsns(insns, name, license, progType, 0)
}

func loadBPFProgramFromInsns(insns asm.Insns, name, license string, progType, attachType uint32) (fd ProgFD, err error) {
	log.Debugf("loadBPFProgramFromInsns(%v, %q, %v, %v, %v)", insns, name, license, progType, attachType)
	utils.IncreaseLockedMemoryQuota()

	// Occasionally see retryable errors here, retry silently a few times before going into log-collection mode.
	backoff := 1 * time.Millisecond
	for retries := 10; retries > 0; retries-- {
		// By default, try to load the program with logging disabled.  This has two advantages: better performance
		// and the fact that the log cannot overflow.
		fd, err = tryLoadBPFProgramFromInsns(insns, name, license, 0, progType, attachType)
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
		fd, err2 := tryLoadBPFProgramFromInsns(insns, name, license, logSize, progType, attachType)
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
			err = err2
		}
		return 0, err
	}
}

func tryLoadBPFProgramFromInsns(insns asm.Insns, name, license string, logSize uint, progType, attachType uint32) (ProgFD, error) {
	log.Debugf("tryLoadBPFProgramFromInsns(..., %s, %v, %v, %v)", name, license, logSize, progType)
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

	fd, err := C.bpf_load_prog(cName, (C.uint)(progType), (C.uint)(attachType), cInsnBytes, C.uint(len(insns)), cLicense,
		(C.uint)(logLevel), (C.uint)(logSize), logBuf)
	if err != nil {
		errno, _ := err.(syscall.Errno)

		if errno != 0 && errno != unix.ENOSPC /* log buffer too small */ {
			goLog := strings.TrimSpace(C.GoString((*C.char)(logBuf)))
			log.WithError(errno).Debug("BPF_PROG_LOAD failed")
			if len(goLog) > 0 {
				lines := strings.Split(goLog, "\n")
				for _, l := range lines {
					log.Error("BPF_PROG_LOAD failed, BPF Verifier output:    ", l)
				}
				if errno == 524 /* Linux ENOTSUPP */ && len(lines) == 1 {
					// likely a JIT error, verifier passed
					// XXX we could test if it says Processed x instructions, but
					// the message may change
					return 0, fmt.Errorf("likely a JIT error, bpf_harden may be set: %w", unix.ERANGE)
				}
			} else if logSize > 0 {
				log.Error("BPF_PROG_LOAD failed, verifier log was empty.")
			}
		}

		if errno != 0 {
			return 0, errno
		}
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
	pr.Duration = time.Duration(C.bpf_attr_prog_run_duration(bpfAttr))
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
