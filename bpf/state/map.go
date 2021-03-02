// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.

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

package state

import (
	"unsafe"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/bpf"
)

type PolicyResult int32

const (
	PolicyNoMatch PolicyResult = iota
	PolicyAllow
	PolicyDeny
	PolicyTailCallFailed = 10
)

// struct cali_tc_state {
//    __be32 ip_src;4
//    __be32 ip_dst;8
//    __be32 post_nat_ip_dst;12
//    __be32 nat_tun_src;16
//    enum calico_policy_result pol_rc;24
//    __u16 sport;26
//    __u16 dport;28
//    __u16 post_nat_dport;30
//    __u8 ip_proto;31
//    __u8 pad;
//    struct calico_ct_result ct_result;
//    struct calico_nat_dest nat_dest;
//    __u64 prog_start_time;
// };
type State struct {
	SrcAddr             uint32
	DstAddr             uint32
	PreNATDstAddr       uint32
	PostNATDstAddr      uint32
	NATTunSrcAddr       uint32
	PolicyRC            PolicyResult
	SrcPort             uint16
	DstPort             uint16
	PreNATDstPort       uint16
	PostNATDstPort      uint16
	IPProto             uint8
	Flags               uint8
	ConntrackRCFlags    uint32
	ConntrackNATIPPort  uint64
	ConntrackTunIP      uint32
	ConntrackIfIndexFwd uint32
	ConntrackIfIndexCtd uint32
	NATData             uint64
	ProgStartTime       uint64
}

const expectedSize = 80

func (s *State) AsBytes() []byte {
	size := unsafe.Sizeof(State{})
	if size != expectedSize {
		log.WithField("size", size).Panic("Incorrect struct size")
	}
	bPtr := (*[expectedSize]byte)(unsafe.Pointer(s))
	bytes := make([]byte, expectedSize)
	copy(bytes, bPtr[:])
	return bytes
}

func StateFromBytes(bytes []byte) State {
	s := State{}
	bPtr := (*[expectedSize]byte)(unsafe.Pointer(&s))
	copy(bPtr[:], bytes)
	return s
}

func Map(mc *bpf.MapContext) bpf.Map {
	return mc.NewPinnedMap(bpf.MapParameters{
		Filename:   "/sys/fs/bpf/tc/globals/cali_v4_state",
		Type:       "percpu_array",
		KeySize:    4,
		ValueSize:  expectedSize,
		MaxEntries: 1,
		Name:       "cali_v4_state",
		Version:    3,
	})
}

func MapForTest(mc *bpf.MapContext) bpf.Map {
	return mc.NewPinnedMap(bpf.MapParameters{
		Filename:   "/sys/fs/bpf/tc/globals/test_v4_state",
		Type:       "array",
		KeySize:    4,
		ValueSize:  expectedSize,
		MaxEntries: 1,
		Name:       "test_v4_state",
	})
}
