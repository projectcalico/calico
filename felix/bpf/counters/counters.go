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
	"runtime"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/libbpf"
	"github.com/sirupsen/logrus"
)

const (
	maxCounterSize int = 8
	uint32Size     int = 4
)

type Counters struct {
	numOfCpu int
	Map      bpf.Map
	iface    string
	hook     string
}

func NewCounters(iface, hook string) *Counters {
	var err error
	cntr := Counters{
		iface: iface,
		hook:  hook,
	}
	cntr.numOfCpu, err = libbpf.NumPossibleCPUs()
	if err != nil {
		logrus.WithError(err).Error("failed to get libbpf number of possible cpu. Will use runtime information")
		cntr.numOfCpu = runtime.NumCPU()
	}
	cntr.Map = Map(&bpf.MapContext{})
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

	bpfCounters := make([]uint32, maxCounterSize)
	for i := range bpfCounters {
		for cpu := 0; cpu < c.numOfCpu; cpu++ {
			begin := i*uint32Size + cpu*maxCounterSize*uint32Size
			bpfCounters[i] += uint32(binary.LittleEndian.Uint32(values[begin : begin+uint32Size]))
		}
	}
	return bpfCounters, nil
}
