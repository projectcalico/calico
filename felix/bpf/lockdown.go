// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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
	"os"
	"strings"
)

const lockdownPath = "/sys/kernel/security/lockdown"

// KernelLockdownConfidentiality reports whether the kernel lockdown LSM is
// active at "confidentiality" level. At that level the kernel disables ftrace
// at boot (tracer_alloc_buffers returns -EPERM), so loading any BPF program
// that references the bpf_trace_printk/bpf_trace_vprintk helper makes the
// kernel log "could not enable bpf_trace_printk events" on every load. When
// this returns true, Felix loads trace-printk-free variants of the preamble
// programs to avoid that log spam.
//
// It returns false when lockdown is off, at a lower level, or the state cannot
// be determined (securityfs not mounted, file absent) — i.e. it never turns on
// the workaround speculatively.
func KernelLockdownConfidentiality() bool {
	return kernelLockdownConfidentiality(lockdownPath)
}

func kernelLockdownConfidentiality(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	// The file lists the available modes with the active one in brackets, e.g.
	// "none integrity [confidentiality]".
	return strings.Contains(string(data), "[confidentiality]")
}
