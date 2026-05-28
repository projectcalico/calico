//go:build !linux

// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.
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

// RegisterHandlers is a no-op on non-Linux platforms. SIGUSR1/SIGUSR2 are not
// available; callers needing on-demand profiling can call DumpHeap or DumpCPU
// directly from their own signal/RPC plumbing.
func RegisterHandlers(opts Options) {}
