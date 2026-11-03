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

package nat

import (
	"encoding/binary"
	"net"
	"testing"

	. "github.com/onsi/gomega"
)

// TestAffinityValueLayout pins the Go view of struct calico_nat_affinity_val
// (felix/bpf-gpl/nat_types.h) to its C layout: an 8-byte calico_nat_dest
// followed by the 64-bit ts at offset 8.
func TestAffinityValueLayout(t *testing.T) {
	RegisterTestingT(t)

	backend := NewNATBackendValue(net.IPv4(10, 20, 30, 40), 666)
	ts := uint64(1234567890123)

	var raw [affinityValueSize]byte
	copy(raw[0:4], backend.Addr().To4())
	binary.LittleEndian.PutUint16(raw[4:6], backend.Port())
	// raw[6:8] is the padding at the tail of calico_nat_dest.
	binary.LittleEndian.PutUint64(raw[8:16], ts)

	v := AffinityValueFromBytes(raw[:])
	Expect(uint64(v.Timestamp())).To(Equal(ts))
	Expect(v.Backend()).To(Equal(backend))

	Expect(NewAffinityValue(ts, backend).AsBytes()).To(Equal(raw[:]))
}

// TestAffinityValueV6Layout pins the Go view of struct calico_nat_affinity_val
// (felix/bpf-gpl/nat_types.h with IPVER6) to its C layout: a 20-byte
// calico_nat_dest, 4 bytes of explicit padding that align the 64-bit ts, and
// the ts at offset 24.
func TestAffinityValueV6Layout(t *testing.T) {
	RegisterTestingT(t)

	backend := NewNATBackendValueV6(net.ParseIP("dead:beef::1234"), 666)
	ts := uint64(1234567890123)

	var raw [affinityValueV6Size]byte
	copy(raw[0:16], backend.Addr().To16())
	binary.LittleEndian.PutUint16(raw[16:18], backend.Port())
	// raw[18:20] is the padding at the tail of calico_nat_dest, raw[20:24]
	// the explicit __pad that aligns ts.
	binary.LittleEndian.PutUint64(raw[24:32], ts)

	v := AffinityValueV6FromBytes(raw[:])
	Expect(uint64(v.Timestamp())).To(Equal(ts))
	Expect(v.Backend()).To(Equal(backend))

	Expect(NewAffinityValueV6(ts, backend).AsBytes()).To(Equal(raw[:]))
}

func TestAffinityKeyV6ClientIP(t *testing.T) {
	RegisterTestingT(t)

	clientIP := net.ParseIP("dead:beef::5678")
	k := NewAffinityKeyV6(clientIP, NewNATKeyV6(net.ParseIP("dead:beef::1234"), 80, 6))

	Expect(k.ClientIP().To16()).To(Equal(clientIP.To16()))
}
