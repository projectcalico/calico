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

	"github.com/projectcalico/calico/felix/bpf"
)

const (
	// PrefixLen (4) + Port (2) + Proto (1) + Flags (1) + IP (4)
	KeySize   = 12
	ValueSize = 4

	FlagOutbound = 1

	// sizeof(port) + sizeof(proto) + sizeof(flags)
	ZeroCIDRPrefixLen = 32
)

type Key struct {
	Port    uint16
	IPProto uint8
	Flags   uint8
	IP      string
	IPMask  int
}

func (k Key) String() string {
	flags := "inbound"
	if k.Flags&FlagOutbound != 0 {
		flags = "outbound"
	}

	return fmt.Sprintf("Key{Port: %d, Proto: %d, Flags: %s, Net: %s/%d",
		k.Port, k.IPProto, flags, k.IP, k.IPMask)
}

var MapParams = bpf.MapParameters{
	Filename:   "/sys/fs/bpf/tc/globals/cali_v4_fsafes",
	Type:       "lpm_trie",
	KeySize:    KeySize,
	ValueSize:  ValueSize,
	MaxEntries: 65536,
	Name:       "cali_v4_fsafes",
	Flags:      unix.BPF_F_NO_PREALLOC,
	Version:    2,
}

func Map(mc *bpf.MapContext) bpf.Map {
	return mc.NewPinnedMap(MapParams)
}

func MakeKey(ipProto uint8, port uint16, outbound bool, ip string, mask int) Key {
	var flags uint8
	if outbound {
		flags |= FlagOutbound
	}
	return Key{
		Port:    port,
		IPProto: ipProto,
		Flags:   flags,
		IP:      ip,
		IPMask:  mask,
	}
}

func (k Key) ToSlice() []byte {
	key := make([]byte, KeySize)
	binary.LittleEndian.PutUint32(key[:4], uint32(ZeroCIDRPrefixLen)+uint32(k.IPMask))
	binary.LittleEndian.PutUint16(key[4:6], k.Port)
	key[6] = k.IPProto
	key[7] = k.Flags
	ip := net.ParseIP(k.IP).To4()
	maskedIP := ip.Mask(net.CIDRMask(k.IPMask, 32))
	for i := 0; i < 4; i++ {
		key[8+i] = maskedIP.To4()[i]
	}
	return key
}

func KeyFromSlice(data []byte) Key {
	var k Key
	k.Port = binary.LittleEndian.Uint16(data[4:6])
	k.IPProto = data[6]
	k.Flags = data[7]

	prefixLen := binary.LittleEndian.Uint32(data[:4])
	k.IPMask = int(prefixLen) - ZeroCIDRPrefixLen
	ipBytes := make([]byte, 4)
	for i := 8; i < len(data); i++ {
		ipBytes[i-8] = data[i]
	}
	k.IP = net.IPv4(ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3]).String()

	return k
}

func Value() []byte {
	return make([]byte, ValueSize) // value is unused for now.
}
