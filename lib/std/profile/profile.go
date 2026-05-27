// Copyright (c) 2016-2026 Tigera, Inc. All rights reserved.
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

// Package profile provides runtime profile dumping triggered by OS signals.
//
// On Linux, SIGUSR1 dumps a heap profile and SIGUSR2 dumps a 10-second CPU
// profile, each to a configured path. On non-Linux platforms RegisterHandlers
// is a no-op (the OS signals don't exist).
package profile

import (
	"os"
	"runtime/pprof"
	"strings"
	"time"

	"github.com/projectcalico/calico/lib/std/log"
)

// Options configures the profiling signal handlers. An empty path for either
// field disables that handler.
type Options struct {
	// HeapProfilePath is the destination file for SIGUSR1-triggered heap
	// dumps. The literal substring "<timestamp>" is replaced with the
	// current time when each profile is written.
	HeapProfilePath string

	// CPUProfilePath is the destination file for SIGUSR2-triggered
	// 10-second CPU profiles. "<timestamp>" is replaced as above.
	CPUProfilePath string
}

// DumpHeap writes a heap profile to fileName. "<timestamp>" in fileName is
// replaced with the current time before opening the file.
func DumpHeap(fileName string) {
	logger := log.WithField("file", fileName)
	logger.Info("Asked to create a memory profile.")
	fileName = renderFileName(fileName)

	f, err := os.Create(fileName)
	if err != nil {
		logger.WithError(err).Error("Could not create memory profile file")
		return
	}
	defer func() { _ = f.Close() }()

	logger.Info("Writing memory profile...")
	if err := pprof.WriteHeapProfile(f); err != nil {
		logger.WithError(err).Error("Could not write memory profile")
		return
	}
	logger.Info("Finished writing memory profile")
}

// DumpCPU writes a 10-second CPU profile to fileName. "<timestamp>" in
// fileName is replaced with the current time before opening the file.
func DumpCPU(fileName string) {
	logger := log.WithField("file", fileName)
	logger.Info("Asked to create a CPU profile.")
	fileName = renderFileName(fileName)

	f, err := os.Create(fileName)
	if err != nil {
		logger.WithError(err).Error("Could not create CPU profile file")
		return
	}
	defer func() { _ = f.Close() }()

	logger.Info("Writing CPU profile...")
	if err := pprof.StartCPUProfile(f); err != nil {
		logger.WithError(err).Error("Could not start CPU profile")
		return
	}
	defer pprof.StopCPUProfile()
	time.Sleep(10 * time.Second)
	logger.Info("Finished writing CPU profile")
}

func renderFileName(template string) string {
	if !strings.Contains(template, "<timestamp>") {
		return template
	}
	return strings.Replace(template, "<timestamp>", time.Now().Format("2006-01-02-15:04:05"), 1)
}
