// Copyright (c) 2021 Tigera, Inc. All rights reserved.
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

// Copyright (c) 2021  All rights reserved.

package failsafes

import (
	"encoding/binary"
	"fmt"
	"net"

	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/bpf/maps"
)

const (
	// PrefixLen (4) + Port (2) + Proto (1) + Flags (1) + IP (16)
	KeyV6Size   = 24
	ValueV6Size = 4
)

type KeyV6 struct {
	port  uint16
	proto uint8
	flags uint8
	addr  string
	mask  int
}

func (k KeyV6) String() string {
	flags := "inbound"
	if k.flags&FlagOutbound != 0 {
		flags = "outbound"
	}

	return fmt.Sprintf("Key{Port: %d, Proto: %d, Flags: %s, Net: %s/%d",
		k.port, k.proto, flags, k.addr, k.mask)
}

var MapV6Params = maps.MapParameters{
	Type:       "lpm_trie",
	KeySize:    KeyV6Size,
	ValueSize:  ValueV6Size,
	MaxEntries: 65536,
	Name:       "cali_v6_fsafes",
	Flags:      unix.BPF_F_NO_PREALLOC,
	Version:    2,
}

func MapV6() maps.Map {
	return maps.NewPinnedMap(MapV6Params)
}

func MakeKeyV6(ipProto uint8, port uint16, outbound bool, ip string, mask int) KeyInterface {
	var flags uint8
	if outbound {
		flags |= FlagOutbound
	}
	return KeyV6{
		port:  port,
		proto: ipProto,
		flags: flags,
		addr:  ip,
		mask:  mask,
	}
}

func (k KeyV6) ToSlice() []byte {
	key := make([]byte, KeyV6Size)
	binary.LittleEndian.PutUint32(key[:4], uint32(ZeroCIDRPrefixLen)+uint32(k.mask))
	binary.LittleEndian.PutUint16(key[4:6], k.port)
	key[6] = k.proto
	key[7] = k.flags
	ip := net.ParseIP(k.addr).To16()
	maskedIP := ip.Mask(net.CIDRMask(k.mask, 128))
	copy(key[8:8+16], maskedIP)
	return key
}

func KeyV6FromSlice(data []byte) KeyInterface {
	var k KeyV6
	k.port = binary.LittleEndian.Uint16(data[4:6])
	k.proto = data[6]
	k.flags = data[7]

	prefixLen := binary.LittleEndian.Uint32(data[:4])
	k.mask = int(prefixLen) - ZeroCIDRPrefixLen
	k.addr = net.IP(data[8 : 8+16]).String()

	return k
}

func ValueV6() []byte {
	return make([]byte, ValueV6Size) // value is unused for now.
}
