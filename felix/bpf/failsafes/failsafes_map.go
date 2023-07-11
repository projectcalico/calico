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

func init() {
	maps.SetSize(MapParams.VersionedName(), MapParams.MaxEntries)
	maps.SetSize(MapV6Params.VersionedName(), MapV6Params.MaxEntries)
}

const (
	// PrefixLen (4) + Port (2) + Proto (1) + Flags (1) + IP (4)
	KeySize   = 12
	ValueSize = 4

	FlagOutbound = 1

	// sizeof(port) + sizeof(proto) + sizeof(flags)
	ZeroCIDRPrefixLen = 32
)

type Key struct {
	port  uint16
	proto uint8
	flags uint8
	addr  string
	mask  int
}

type KeyInterface interface {
	String() string
	ToSlice() []byte
}

func (k Key) String() string {
	flags := "inbound"
	if k.flags&FlagOutbound != 0 {
		flags = "outbound"
	}

	return fmt.Sprintf("Key{Port: %d, Proto: %d, Flags: %s, Net: %s/%d",
		k.port, k.proto, flags, k.addr, k.mask)
}

var MapParams = maps.MapParameters{
	Type:       "lpm_trie",
	KeySize:    KeySize,
	ValueSize:  ValueSize,
	MaxEntries: 65536,
	Name:       "cali_v4_fsafes",
	Flags:      unix.BPF_F_NO_PREALLOC,
	Version:    2,
}

func Map() maps.Map {
	return maps.NewPinnedMap(MapParams)
}

func MakeKey(ipProto uint8, port uint16, outbound bool, ip string, mask int) KeyInterface {
	var flags uint8
	if outbound {
		flags |= FlagOutbound
	}
	return Key{
		port:  port,
		proto: ipProto,
		flags: flags,
		addr:  ip,
		mask:  mask,
	}
}

func (k Key) ToSlice() []byte {
	key := make([]byte, KeySize)
	binary.LittleEndian.PutUint32(key[:4], uint32(ZeroCIDRPrefixLen)+uint32(k.mask))
	binary.LittleEndian.PutUint16(key[4:6], k.port)
	key[6] = k.proto
	key[7] = k.flags
	ip := net.ParseIP(k.addr).To4()
	maskedIP := ip.Mask(net.CIDRMask(k.mask, 32))
	copy(key[8:8+4], maskedIP)
	return key
}

func KeyFromSlice(data []byte) KeyInterface {
	var k Key
	k.port = binary.LittleEndian.Uint16(data[4:6])
	k.proto = data[6]
	k.flags = data[7]

	prefixLen := binary.LittleEndian.Uint32(data[:4])
	k.mask = int(prefixLen) - ZeroCIDRPrefixLen
	k.addr = net.IPv4(data[8], data[8+1], data[8+2], data[8+3]).String()

	return k
}

func Value() []byte {
	return make([]byte, ValueSize) // value is unused for now.
}
