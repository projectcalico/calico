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
	ErrFailedCSUM
	AcceptedByFailsafe
	AcceptedByPolicy
	DroppedByPolicy
)

const (
	HookIngress = "ingress"
	HookEgress  = "egress"
)

var Hooks = []string{HookIngress, HookEgress}

type Counters struct {
	maps     map[string]bpf.Map
	numOfCpu int
	iface    string
}

func NewCounters(iface string) *Counters {
	cntr := Counters{
		iface: iface,
	}
	var err error
	cntr.numOfCpu, err = libbpf.NumPossibleCPUs()
	if err != nil {
		logrus.WithError(err).Error("failed to get libbpf number of possible cpu. Will use runtime information")
		cntr.numOfCpu = runtime.NumCPU()
	}

	cntr.maps = make(map[string]bpf.Map)
	pinPath := tc.MapPinPath(unix.BPF_MAP_TYPE_PERCPU_ARRAY,
		bpf.CountersMapName(), iface, tc.HookIngress)
	cntr.maps[HookIngress] = Map(&bpf.MapContext{}, pinPath)
	logrus.Debugf("ingress counter map pin path: %v", pinPath)

	pinPath = tc.MapPinPath(unix.BPF_MAP_TYPE_PERCPU_ARRAY,
		bpf.CountersMapName(), iface, tc.HookEgress)
	cntr.maps[HookEgress] = Map(&bpf.MapContext{}, pinPath)
	logrus.Debugf("egress counter map pin path: %v", pinPath)

	return &cntr
}

func (c Counters) Read(hook string) ([]uint32, error) {
	return c.read(c.maps[hook])
}

func (c Counters) read(cMap bpf.Map) ([]uint32, error) {
	err := cMap.Open()
	if err != nil {
		return []uint32{}, fmt.Errorf("failed to open counters map. err=%v", err)
	}
	defer func() {
		err := cMap.Close()
		if err != nil {
			logrus.WithError(err).Errorf("failed to close counters map.")
		}
	}()

	// k is the key to the counters map, and it is set to 0 since there is only one entry
	k := make([]byte, uint32Size)
	values, err := cMap.Get(k)
	if err != nil {
		return []uint32{}, fmt.Errorf("failed to read counters map. err=%v", err)
	}

	bpfCounters := make([]uint32, MaxCounterNumber)
	for i := range bpfCounters {
		for cpu := 0; cpu < c.numOfCpu; cpu++ {
			begin := i*uint32Size + cpu*MaxCounterNumber*uint32Size
			bpfCounters[i] += uint32(binary.LittleEndian.Uint32(values[begin : begin+uint32Size]))
		}
	}
	return bpfCounters, nil
}

func (c *Counters) Flush() error {
	for _, hook := range Hooks {
		err := c.flush(c.maps[hook])
		if err != nil {
			return fmt.Errorf("Failed to flush bpf counters for interface=%s hook=%s. err=%v", c.iface, hook, err)
		}
		logrus.Infof("Successfully flushed counters map for interface=%s hook=%s", c.iface, hook)
	}
	return nil
}

func (c *Counters) flush(cMap bpf.Map) error {
	err := cMap.Open()
	if err != nil {
		return fmt.Errorf("failed to open counters map. err=%v", err)
	}
	defer func() {
		err := cMap.Close()
		if err != nil {
			logrus.WithError(err).Errorf("failed to close counters map.")
		}
	}()

	// k is the key to the counters map, and it is set to 0 since there is only one entry
	k := make([]byte, uint32Size)
	v := make([]byte, uint32Size*MaxCounterNumber*c.numOfCpu)
	err = cMap.Update(k, v)
	if err != nil {
		return fmt.Errorf("failed to update counters map. err=%v", err)
	}
	return nil
}
