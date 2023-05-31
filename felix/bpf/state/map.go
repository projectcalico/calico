// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.

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

	"github.com/projectcalico/calico/felix/bpf/maps"
)

func init() {
	maps.SetSize(MapParameters.VersionedName(), MapParameters.MaxEntries)
}

type PolicyResult int32

const (
	PolicyNoMatch PolicyResult = iota
	PolicyAllow
	PolicyDeny
	PolicyTailCallFailed = 10
	MaxRuleIDs           = 32
)

//	struct cali_tc_state {
//	   __be32 ip_src;
//	   __be32 ip_src1;
//	   __be32 ip_src2;
//	   __be32 ip_src3;
//	   __be32 ip_dst;
//	   __be32 ip_dst1;
//	   __be32 ip_dst2;
//	   __be32 ip_dst3;
//	   __be32 pre_nat_ip_dst;
//	   __be32 pre_nat_ip_dst1;
//	   __be32 pre_nat_ip_dst2;
//	   __be32 pre_nat_ip_dst3;
//	   __be32 post_nat_ip_dst;
//	   __be32 post_nat_ip_dst1;
//	   __be32 post_nat_ip_dst2;
//	   __be32 post_nat_ip_dst3;
//	   __be32 tun_ip;
//	   __be32 tun_ip1;
//	   __be32 tun_ip2;
//	   __be32 tun_ip3;
//	   __u32 unused;
//	   __s32 pol_rc;
//	   __u16 sport;
//	   __u16 dport;
//	   __u16 pre_nat_dport;
//	   __u16 post_nat_dport;
//	   __u8 ip_proto;
//	   __u8 __pad;
//	   __be16 ip_size;
//	   __u32 rules_hit;
//	   __u64 rule_ids[MAX_RULE_IDS];
//	   struct calico_ct_result ct_result;
//	   struct calico_nat_dest nat_dest;
//	   __u64 prog_start_time;
//	   __u64 flags;
//	};
type State struct {
	SrcAddr             uint32
	SrcAddr1            uint32
	SrcAddr2            uint32
	SrcAddr3            uint32
	DstAddr             uint32
	DstAddr1            uint32
	DstAddr2            uint32
	DstAddr3            uint32
	PreNATDstAddr       uint32
	PreNATDstAddr1      uint32
	PreNATDstAddr2      uint32
	PreNATDstAddr3      uint32
	PostNATDstAddr      uint32
	PostNATDstAddr1     uint32
	PostNATDstAddr2     uint32
	PostNATDstAddr3     uint32
	TunIP               uint32
	TunIP1              uint32
	TunIP2              uint32
	TunIP3              uint32
	ihl                 uint16
	_                   uint16
	PolicyRC            PolicyResult
	SrcPort             uint16
	DstPort             uint16
	PreNATDstPort       uint16
	PostNATDstPort      uint16
	IPProto             uint8
	pad                 uint8
	IPSize              uint16
	RulesHit            uint32
	RuleIDs             [MaxRuleIDs]uint64
	ConntrackRCFlags    uint32
	_                   uint32
	ConntrackNATIPPort  uint64
	ConntrackTunIP      uint32
	ConntrackIfIndexFwd uint32
	ConntrackIfIndexCtd uint32
	_                   uint32
	NATData             uint64
	ProgStartTime       uint64
	Flags               uint64
}

const expectedSize = 416

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

var MapParameters = maps.MapParameters{
	Type:       "percpu_array",
	KeySize:    4,
	ValueSize:  expectedSize,
	MaxEntries: 2,
	Name:       "cali_state",
	Version:    3,
}

func Map() maps.Map {
	return maps.NewPinnedMap(MapParameters)
}

func MapForTest() maps.Map {
	return maps.NewPinnedMap(maps.MapParameters{
		Type:       "array",
		KeySize:    4,
		ValueSize:  expectedSize,
		MaxEntries: 2,
		Name:       "test_state",
	})
}
