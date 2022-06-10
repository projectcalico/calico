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

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/libbpf"
	"github.com/projectcalico/calico/felix/bpf/tc"
)

const (
	MaxCounterNumber int = 8
	uint32Size       int = 4
)

const (
	TotalPackets = iota
	ErrShortPacket
	AcceptedByPolicy
	DroppedByPolicy
)

type Counters struct {
	ingressMap bpf.Map
	egressMap  bpf.Map
	iface      string
}

func NewCounters(iface string) *Counters {
	cntr := Counters{
		iface: iface,
	}
	pinPath := tc.MapPinPath(unix.BPF_MAP_TYPE_PERCPU_ARRAY, bpf.CountersMapName(), iface, tc.HookIngress)
	cntr.ingressMap = Map(&bpf.MapContext{}, pinPath)
	logrus.Debugf("Ingress counter map pin path: %v", pinPath)

	pinPath = tc.MapPinPath(unix.BPF_MAP_TYPE_PERCPU_ARRAY, bpf.CountersMapName(), iface, tc.HookEgress)
	cntr.egressMap = Map(&bpf.MapContext{}, pinPath)
	logrus.Debugf("Egress counter map pin path: %v", pinPath)
	return &cntr
}

func (c *Counters) ReadIngress() ([]uint32, error) {
	return read(c.ingressMap)
}

func (c *Counters) ReadEgress() ([]uint32, error) {
	return read(c.egressMap)
}

func (c *Counters) FlushIngress() error {
	return flush(c.ingressMap)
}

func (c *Counters) FlushEgress() error {
	return flush(c.egressMap)
}

func read(Map bpf.Map) ([]uint32, error) {
	err := Map.Open()
	if err != nil {
		return []uint32{}, fmt.Errorf("failed to open counters map. err=%v", err)
	}
	defer func() {
		err := Map.Close()
		if err != nil {
			logrus.WithError(err).Errorf("failed to close counters map.")
		}
	}()

	numOfCpu, err := libbpf.NumPossibleCPUs()
	if err != nil {
		return []uint32{}, fmt.Errorf("failed to get number of possible cpu. err=%v", err)
	}

	// k is the key to the counters map, and it is set to 0 since there is only one entry
	k := make([]byte, uint32Size)
	values, err := Map.Get(k)
	if err != nil {
		return []uint32{}, fmt.Errorf("failed to read counters map. err=%v", err)
	}

	bpfCounters := make([]uint32, MaxCounterNumber)
	for i := range bpfCounters {
		for cpu := 0; cpu < numOfCpu; cpu++ {
			begin := i*uint32Size + cpu*MaxCounterNumber*uint32Size
			bpfCounters[i] += uint32(binary.LittleEndian.Uint32(values[begin : begin+uint32Size]))
		}
	}
	return bpfCounters, nil
}

func flush(Map bpf.Map) error {
	err := Map.Open()
	if err != nil {
		return fmt.Errorf("failed to open counters map. err=%v", err)
	}
	defer func() {
		err := Map.Close()
		if err != nil {
			logrus.WithError(err).Errorf("failed to close counters map.")
		}
	}()

	numOfCpu, err := libbpf.NumPossibleCPUs()
	if err != nil {
		return fmt.Errorf("failed to get number of possible cpu. err=%v", err)
	}

	// k is the key to the counters map, and it is set to 0 since there is only one entry
	k := make([]byte, uint32Size)
	v := make([]byte, uint32Size*MaxCounterNumber*numOfCpu)
	err = Map.Update(k, v)
	if err != nil {
		return fmt.Errorf("failed to update counters map. err=%v", err)
	}
	return nil
}
