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

package testutils

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync/atomic"
)

// TestBlockAllocator hands out IPs from distinct CIDR blocks within a pool.
// In Ordered test suites with a shared IPAM controller, the controller's
// async block GC from test N can race with test N+1's allocations on the
// same block. Allocating from a different block per test eliminates this.
type TestBlockAllocator struct {
	baseIP    uint32
	blockSize uint32
	next      uint32
}

// NewTestBlockAllocator creates an allocator that returns IPs from successive
// blocks within the given pool. blockBits is the CIDR prefix length of each
// block (e.g., 26 for /26 blocks of 64 IPs).
func NewTestBlockAllocator(poolBase string, blockBits int) *TestBlockAllocator {
	ip := net.ParseIP(poolBase).To4()
	if ip == nil {
		panic(fmt.Sprintf("invalid IPv4 address: %s", poolBase))
	}
	return &TestBlockAllocator{
		baseIP:    binary.BigEndian.Uint32(ip),
		blockSize: 1 << uint(32-blockBits),
	}
}

// NextIP returns the first usable IP (.1 offset) in the next unused block.
// Safe for concurrent use.
func (a *TestBlockAllocator) NextIP() string {
	n := atomic.AddUint32(&a.next, 1) - 1
	ipNum := a.baseIP + n*a.blockSize + 1
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipNum)
	return ip.String()
}
