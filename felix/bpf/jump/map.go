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
	// MaxSubPrograms is the maximum number of policy sub-programs that
	// we allow for a single hook.  BPF allows a maximum of 32 tail calls
	// (so 33 chained programs in total) but we reserve some for our own use.
	MaxSubPrograms = 24

	// TCMaxEntryPoints is the maximum number of policy program entry points
	// (i.e. first program in a chain of sub-programs for the policy).
	TCMaxEntryPoints = 10000
	// TCMaxEntries is the size fo the map, i.e. all possible sub-programs.
	TCMaxEntries = TCMaxEntryPoints * MaxSubPrograms

	XDPMaxEntryPoints = 100
	XDPMaxEntries     = XDPMaxEntryPoints * MaxSubPrograms
)

var IngressMapParameters = maps.MapParameters{
	Type:       "prog_array",
	KeySize:    4,
	ValueSize:  4,
	MaxEntries: TCMaxEntries,
	Name:       "cali_jump_ing",
	Version:    2,
}

var EgressMapParameters = maps.MapParameters{
	Type:       "prog_array",
	KeySize:    4,
	ValueSize:  4,
	MaxEntries: TCMaxEntries,
	Name:       "cali_jump_egr",
	Version:    2,
}

func Maps() []maps.Map {
	return []maps.Map{
		maps.NewPinnedMap(IngressMapParameters),
		maps.NewPinnedMap(EgressMapParameters),
	}
}

var XDPMapParameters = maps.MapParameters{
	Type:       "prog_array",
	KeySize:    4,
	ValueSize:  4,
	MaxEntries: XDPMaxEntries,
	Name:       "xdp_cali_jump",
	Version:    3,
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
