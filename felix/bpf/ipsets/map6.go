// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

package ipsets

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/ip"
)

// WARNING: must be kept in sync with the definitions in bpf/polprog/pol_prog_builder.go.
// WARNING: must be kept in sync with the definitions in bpf/include/policy.h.
// uint32 prefixLen HE  4
// uint64 set_id BE     +8 = 12
// 4*uint32 addr BE     +16 = 28
// uint16 port HE       +2 = 30
// uint8 proto          +1 = 31
// uint8 pad            +1 = 32
const IPSetEntryV6Size = 32

type IPSetEntryV6 [IPSetEntryV6Size]byte

var MapV6Parameters = maps.MapParameters{
	Type:       "lpm_trie",
	KeySize:    IPSetEntryV6Size,
	ValueSize:  4,
	MaxEntries: 1024 * 1024,
	Name:       "cali_v6_ip_sets",
	Flags:      unix.BPF_F_NO_PREALLOC,
}

func SetMapV6Size(size int) {
	maps.SetSize(MapV6Parameters.VersionedName(), size)
}

func MapV6() maps.Map {
	return maps.NewPinnedMap(MapV6Parameters)
}

func (e IPSetEntryV6) AsBytes() []byte {
	return e[:]
}

func (e IPSetEntryV6) SetID() uint64 {
	return binary.BigEndian.Uint64(e[4:12])
}

func (e IPSetEntryV6) Addr() net.IP {
	return e[12:28]
}

func (e IPSetEntryV6) PrefixLen() uint32 {
	return binary.LittleEndian.Uint32(e[:4])
}

func (e IPSetEntryV6) Protocol() uint8 {
	return e[30]
}

func (e IPSetEntryV6) Port() uint16 {
	return binary.LittleEndian.Uint16(e[28:30])
}

func (e IPSetEntryV6) String() string {
	return fmt.Sprintf("0x%08x %20s prefix %d port %d  proto %d", e.SetID(), e.Addr(), e.PrefixLen(), e.Port(), e.Protocol())
}

func IPSetEntryV6FromBytes(b []byte) IPSetEntryInterface {
	var e IPSetEntryV6
	copy(e[:], b)
	return e
}

func MakeBPFIPSetEntryV6(setID uint64, cidr ip.V6CIDR, port uint16, proto uint8) IPSetEntryInterface {
	var entry IPSetEntryV6
	// TODO Detect endianness
	if proto == 0 {
		// Normal CIDR-based lookup.
		binary.LittleEndian.PutUint32(entry[0:4], uint32(64 /* ID */ +cidr.Prefix()))
	} else {
		// Named port lookup, use full length of key.
		binary.LittleEndian.PutUint32(entry[0:4], 64 /* ID */ +128 /* IP */ +16 /* Port */ +8 /* protocol */)
	}
	binary.BigEndian.PutUint64(entry[4:12], setID)
	ipv6 := cidr.Addr().(ip.V6Addr)
	copy(entry[12:28], ipv6[:])
	binary.LittleEndian.PutUint16(entry[28:30], port)
	entry[30] = proto
	return entry
}

func ProtoIPSetMemberToBPFEntryV6(id uint64, member string) IPSetEntryInterface {
	var cidrStr string
	var port uint16
	var protocol uint8
	if strings.Contains(member, ",") {
		// Named port
		parts := strings.Split(member, ",")
		cidrStr = parts[0]
		parts = strings.Split(parts[1], ":")
		switch parts[0] {
		case "tcp":
			protocol = 6
		case "udp":
			protocol = 17
		default:
			logrus.WithField("member", member).Warn("Unknown protocol in named port member")
			return nil
		}
		port64, err := strconv.ParseUint(parts[1], 10, 16)
		if err != nil {
			logrus.WithField("member", member).WithError(err).Panic("Failed to parse port")
		}
		port = uint16(port64)
	} else {
		cidrStr = member
	}
	cidr, v6 := ip.MustParseCIDROrIP(cidrStr).(ip.V6CIDR)
	if !v6 {
		return nil
	}
	entry := MakeBPFIPSetEntryV6(id, cidr, port, protocol)
	return entry
}

type MapMemV6 map[IPSetEntryV6]struct{}

func MapMemV6Iter(m MapMemV6) func(k, v []byte) {
	ks := len(IPSetEntryV6{})

	return func(k, v []byte) {
		var key IPSetEntryV6
		copy(key[:ks], k[:ks])

		m[key] = struct{}{}
	}
}

func (m MapMemV6) String() string {
	var out string

	for k := range m {
		out += k.String() + "\n"
	}

	return out
}
