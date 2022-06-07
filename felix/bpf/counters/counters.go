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

package counters

import (
	"encoding/binary"
	"fmt"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/libbpf"
	"github.com/projectcalico/calico/felix/bpf/tc"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const (
	maxCounterSize int = 8
	uint32Size     int = 4
)

type Counters struct {
	Map   bpf.Map
	iface string
}

func NewCounters(iface string) *Counters {
	cntr := Counters{
		iface: iface,
	}
	pinPath := tc.MapPinPath(unix.BPF_MAP_TYPE_PERCPU_ARRAY, bpf.CountersMapName(), iface, tc.HookIngress)
	cntr.Map = Map(&bpf.MapContext{}, pinPath)
	logrus.Infof("counter path: %v", pinPath)
	return &cntr
}

func (c Counters) Read() ([]uint32, error) {

	/*mapFD, err := bpf.GetCachedMapFDByPin(c.Map)
	if err != nil {
		return []uint32{}, fmt.Errorf("failed to get counters map fd: %v", err)
	}*/

	// k is the key to the counters map, and it is set to 0 since there is only one entry
	k := make([]byte, uint32Size)
	/*values, err := bpf.GetMapEntry(mapFD, k, maxCounterSize*uint32Size*c.numOfCpu)
	if err != nil {
		return []uint32{}, fmt.Errorf("failed to read counters map: %v", err)
	}*/

	values, err := c.Map.Get(k)
	if err != nil {
		return []uint32{}, fmt.Errorf("failed to read counters map: %v", err)
	}

	numOfCpu, err := libbpf.NumPossibleCPUs()
	if err != nil {
		return []uint32{}, fmt.Errorf("failed to get number of possible cpu - err: %v", err)
	}
	bpfCounters := make([]uint32, maxCounterSize)
	for i := range bpfCounters {
		for cpu := 0; cpu < numOfCpu; cpu++ {
			begin := i*uint32Size + cpu*maxCounterSize*uint32Size
			bpfCounters[i] += uint32(binary.LittleEndian.Uint32(values[begin : begin+uint32Size]))
		}
	}
	return bpfCounters, nil
}
