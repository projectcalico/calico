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

	"github.com/projectcalico/calico/felix/bpf"
)

func MapForTest(mc *bpf.MapContext) bpf.Map {
	return mc.NewPinnedMap(bpf.MapParameters{
		Filename:   "/sys/fs/bpf/tc/globals/cali_v4_jump",
		Type:       "prog_array",
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 32,
		Name:       bpf.JumpMapName(),
	})
}

func GetEntry(fd bpf.MapFD, i int) (int, error) {
	var k [4]byte

	binary.LittleEndian.PutUint32(k[:], uint32(i))

	bytes, err := bpf.GetMapEntry(fd, k[:], 4)
	if err != nil {
		return 0, err
	}

	return int(binary.LittleEndian.Uint32(bytes)), nil
}

func DeleteEntry(fd bpf.MapFD, i int) error {
	var k [4]byte

	binary.LittleEndian.PutUint32(k[:], uint32(i))

	return bpf.DeleteMapEntry(fd, k[:], 4)
}
