// Copyright (c) 2022 Tigera, Inc. All rights reserved.
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

package v4

import (
	"encoding/binary"

	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/bpf"
	v5 "github.com/projectcalico/calico/felix/bpf/mock/multiversion/v5"
)

var MockMapParams = bpf.MapParameters{
	Filename:   "/sys/fs/bpf/tc/globals/cali_mock",
	Type:       "hash",
	KeySize:    32,
	ValueSize:  80,
	MaxEntries: 1024,
	Name:       "cali_mock",
	Flags:      unix.BPF_F_NO_PREALLOC,
	Version:    4,
}

const (
	KeySize   = 32
	ValueSize = 80
)

type Key [KeySize]byte

func (k Key) AsBytes() []byte {
	return k[:]
}

func NewKey(k uint32) Key {
	var key Key
	binary.LittleEndian.PutUint32(key[:], k)
	return key
}

type Value [ValueSize]byte

func (v Value) AsBytes() []byte {
	return v[:]
}

func NewValue(v uint32) Value {
	var val Value
	binary.LittleEndian.PutUint32(val[:], v)
	return val
}

func (k Key) Upgrade() bpf.Upgradable {
	var key5 v5.Key
	copy(key5[:], k[:])
	return key5
}

func (v Value) Upgrade() bpf.Upgradable {
	var val5 v5.Value
	copy(val5[:], v[:])
	return val5
}
