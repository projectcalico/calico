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

	"golang.org/x/sys/unix"

	"github.com/projectcalico/felix/bpf"
)

const (
	KeySize   = 4
	ValueSize = 4

	FlagOutbound = 1
)

type Key struct {
	Port    uint16
	IPProto uint8
	Flags   uint8
}

var MapParams = bpf.MapParameters{
	Filename:   "/sys/fs/bpf/tc/globals/cali_v4_fsafes",
	Type:       "hash",
	KeySize:    KeySize,
	ValueSize:  ValueSize,
	MaxEntries: 65536,
	Name:       "cali_v4_fsafes",
	Flags:      unix.BPF_F_NO_PREALLOC,
}

func Map(mc *bpf.MapContext) bpf.Map {
	return mc.NewPinnedMap(MapParams)
}

func MakeKey(ipProto uint8, port uint16, outbound bool) Key {
	var flags uint8
	if outbound {
		flags |= FlagOutbound
	}
	return Key{
		Port:    port,
		IPProto: ipProto,
		Flags:   flags,
	}
}

func (k Key) ToSlice() []byte {
	key := make([]byte, KeySize)
	binary.LittleEndian.PutUint16(key[:2], k.Port)
	key[2] = k.IPProto
	key[3] = k.Flags
	return key
}

func KeyFromSlice(data []byte) Key {
	var k Key
	k.Port = binary.LittleEndian.Uint16(data[:2])
	k.IPProto = data[2]
	k.Flags = data[3]
	return k
}

func Value() []byte {
	return make([]byte, ValueSize) // value is unused for now.
}
