//go:build linux

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

package profile

import (
	"os"
	"os/signal"
	"syscall"
)

// RegisterHandlers wires SIGUSR1 to DumpHeap and SIGUSR2 to DumpCPU using the
// paths from opts. An empty path skips that handler.
func RegisterHandlers(opts Options) {
	if opts.HeapProfilePath != "" {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGUSR1)
		go func() {
			for range ch {
				DumpHeap(opts.HeapProfilePath)
			}
		}()
	}

	if opts.CPUProfilePath != "" {
		ch := make(chan os.Signal, 10)
		signal.Notify(ch, syscall.SIGUSR2)
		go func() {
			for range ch {
				DumpCPU(opts.CPUProfilePath)
			}
		}()
	}
}
