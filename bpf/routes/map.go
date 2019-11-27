// Copyright (c) 2019 Tigera, Inc. All rights reserved.
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

package routes

import (
	"encoding/binary"

	"golang.org/x/sys/unix"

	"github.com/projectcalico/felix/bpf"
	"github.com/projectcalico/felix/ip"
)

//
// struct calico_route_key {
// __u32 mask;
// __be32 addr; // NBO
// };
const KeySize = 8

type Key [KeySize]byte

type Type uint32

const (
	TypeUnknown        Type = 0
	TypeRemoteWorkload      = 1
	TypeRemoteHost          = 2
	TypeLocalHost           = 3
	TypeLocalWorkload       = 4
)

//
// struct calico_route_value {
// enum calico_route_type type;
// __u32 next_hop;
// };
const ValueSize = 8

type Value [ValueSize]byte

func NewKey(cidr ip.V4CIDR) Key {
	var k Key

	binary.LittleEndian.PutUint32(k[:4], uint32(cidr.Prefix()))
	copy(k[4:8], cidr.Addr().AsNetIP().To4())

	return k
}

func NewValueWithNextHop(valueType Type, nextHop ip.V4Addr) Value {
	var v Value
	binary.LittleEndian.PutUint32(v[:4], uint32(valueType))
	copy(v[4:8], nextHop.AsNetIP().To4())
	return v
}

func NewValue(valueType Type) Value {
	var v Value
	binary.LittleEndian.PutUint32(v[:4], uint32(valueType))
	return v
}

var MapParameters = bpf.MapParameters{
	Filename:   "/sys/fs/bpf/tc/globals/cali_routes",
	Type:       "lpm_trie",
	KeySize:    KeySize,
	ValueSize:  ValueSize,
	MaxEntries: 1024 * 1024,
	Name:       "cali_routes",
	Flags:      unix.BPF_F_NO_PREALLOC,
}

func Map() bpf.Map {
	return bpf.NewPinnedMap(MapParameters)
}
