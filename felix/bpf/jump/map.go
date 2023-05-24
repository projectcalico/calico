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

package jump

import (
	"encoding/binary"

	"github.com/projectcalico/calico/felix/bpf/maps"
)

const (
	MaxEntries    = 10000
	XDPMaxEntries = 100
)

var MapParameters = maps.MapParameters{
	Type:       "prog_array",
	KeySize:    4,
	ValueSize:  4,
	MaxEntries: MaxEntries,
	Name:       "cali_jump",
	Version:    2,
}

func Map() maps.Map {
	return maps.NewPinnedMap(MapParameters)
}

var XDPMapParameters = maps.MapParameters{
	Type:       "prog_array",
	KeySize:    4,
	ValueSize:  4,
	MaxEntries: XDPMaxEntries,
	Name:       "xdp_cali_jump",
	Version:    2,
}

func XDPMap() maps.Map {
	return maps.NewPinnedMap(XDPMapParameters)
}

func Key(idx int) []byte {
	var k [4]byte
	binary.LittleEndian.PutUint32(k[:], uint32(idx))
	return k[:]
}

func Value(fd uint32) []byte {
	var v [4]byte
	binary.LittleEndian.PutUint32(v[:], fd)
	return v[:]
}
