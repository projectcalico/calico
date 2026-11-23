// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.

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

// State mirrors the IPv4 struct cali_tc_state, padded to the IPv6 size.
// TestStateLayoutMatchesC checks the c tags against the C layout.
type State struct {
	eventHeader         uint64 `c:"eventhdr"`
	SrcAddr             uint32 `c:"ip_src"`
	SrcAddr1            uint32
	SrcAddr2            uint32
	SrcAddr3            uint32
	DstAddr             uint32 `c:"ip_dst"`
	DstAddr1            uint32
	DstAddr2            uint32
	DstAddr3            uint32
	PreNATDstAddr       uint32 `c:"pre_nat_ip_dst"`
	PreNATDstAddr1      uint32
	PreNATDstAddr2      uint32
	PreNATDstAddr3      uint32
	PostNATDstAddr      uint32 `c:"post_nat_ip_dst"`
	PostNATDstAddr1     uint32
	PostNATDstAddr2     uint32
	PostNATDstAddr3     uint32
	TunIP               uint32 `c:"tun_ip"`
	TunIP1              uint32
	TunIP2              uint32
	TunIP3              uint32
	ihl                 uint16       `c:"ihl"`
	PreNATSrcPort       uint16       `c:"pre_nat_sport"`
	PolicyRC            PolicyResult `c:"pol_rc"`
	SrcPort             uint16       `c:"sport"`
	DstPort             uint16       `c:"dport"`
	PreNATDstPort       uint16       `c:"pre_nat_dport"`
	PostNATDstPort      uint16       `c:"post_nat_dport"`
	IPProto             uint8        `c:"ip_proto"`
	_                   uint8
	IPSize              uint16             `c:"ip_size"`
	RulesHit            uint32             `c:"rules_hit"`
	RuleIDs             [MaxRuleIDs]uint64 `c:"rule_ids"`
	Flags               uint64             `c:"flags"`
	ConntrackRC         int16              `c:"ct_result.rc"`
	ConntrackFwdFlags   uint16             `c:"ct_result.fwd_flags"`
	ConntrackFlags      uint32             `c:"ct_result.flags"`
	ConntrackNATIP      uint32             `c:"ct_result.nat_ip"`
	ConntrackNATsIP     uint32             `c:"ct_result.nat_sip"`
	ConntrackNATPort    uint16             `c:"ct_result.nat_port"`
	ConntrackNATsPort   uint16             `c:"ct_result.nat_sport"`
	ConntrackTunIP      uint32             `c:"ct_result.tun_ip"`
	ConntrackIfIndexFwd uint32             `c:"ct_result.ifindex_fwd"`
	ConntrackIfIndexCtd uint32             `c:"ct_result.ifindex_created"`
	NATDestAddr         uint32             `c:"nat_dest.addr"`
	NATDestPort         uint16             `c:"nat_dest.port"`
	_                   [2]byte
	ProgStartTime       uint64 `c:"prog_start_time"`
	PreNATSrcAddr       uint32 `c:"pre_nat_ip_src"`
	PreNATSrcAddr1      uint32
	PreNATSrcAddr2      uint32
	PreNATSrcAddr3      uint32
	NATSvcID            uint32 `c:"nat_svc_id"`
	// fwd, then padding to the IPv6 size.
	_ [64]byte
}

const expectedSize = 512
const entrySize = 512

func (s *State) AsBytes() []byte {
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
	ValueSize:  entrySize,
	MaxEntries: 2,
	Name:       "cali_state",
	Version:    6,
}

func Map() maps.Map {
	return maps.NewPinnedMap(MapParameters)
}

func MapForTest() maps.Map {
	return maps.NewPinnedMap(maps.MapParameters{
		Type:       "array",
		KeySize:    4,
		ValueSize:  entrySize,
		MaxEntries: 2,
		Name:       "test_state",
	})
}
