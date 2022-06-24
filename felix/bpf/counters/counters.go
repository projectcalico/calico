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
	"github.com/projectcalico/calico/felix/bpf/tc"
)

const (
	MaxCounterNumber int = 14
	uint32Size       int = 4
)

// The following values are used as index to counters map, and should be kept in sync
// with constants defined in bpf-gpl/reasons.h.
const (
	TotalPackets = iota
	AcceptedByFailsafe
	AcceptedByPolicy
	AcceptedByAnotherProgram
	DroppedByPolicy
	DroppedShortPacket
	DroppedFailedCSUM
	DroppedIPOptions
	DroppredIPMalformed
	DroppedFailedEncap
	DroppedFailedDecap
	DroppedUnauthSource
	DroppedUnknownRoute
)

var Descriptions map[int]string = map[int]string{
	TotalPackets:             "Total packets",
	AcceptedByFailsafe:       "Accepted by failsafe",
	AcceptedByPolicy:         "Accepted by policy",
	AcceptedByAnotherProgram: "Accepted by another program",
	DroppedByPolicy:          "Dropped by policy",
	DroppedShortPacket:       "Dropped too short packets",
	DroppedFailedCSUM:        "Dropped incorrect checksum",
	DroppedIPOptions:         "Dropped packets with unsupported IP options",
	DroppredIPMalformed:      "Dropped malformed IP packets",
	DroppedFailedEncap:       "Dropped failed encapsulation",
	DroppedFailedDecap:       "Dropped failed decapsulation",
	DroppedUnauthSource:      "Dropped packets with unknown source",
	DroppedUnknownRoute:      "Dropped packets with unknown route",
}

const (
	HookIngress = iota
	HookEgress
)

var HooksName = []string{"ingress", "egress"}

type Counters struct {
	iface    string
	numOfCpu int
	maps     []bpf.Map
}

func NewCounters(iface string) *Counters {
	cntr := Counters{
		iface:    iface,
		numOfCpu: bpf.NumPossibleCPUs(),
		maps:     make([]bpf.Map, len(HooksName)),
	}

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

func (c Counters) Read() ([][]uint32, error) {
	values := make([][]uint32, len(HooksName))
	for i := range values {
		values[i] = make([]uint32, MaxCounterNumber)
	}

	for hook, name := range HooksName {
		val, err := c.read(c.maps[hook])
		if err != nil {
			return values, fmt.Errorf("Failed to read bpf counters. hook=%s err=%v", name, err)
		}
		if len(values[hook]) < MaxCounterNumber {
			return values, fmt.Errorf("Failed to read enough data from bpf counters. hook=%s", name)
		}

		values[hook] = val
	}

	return values, nil
}

func (c Counters) read(cMap bpf.Map) ([]uint32, error) {
	err := cMap.Open()
	if err != nil {
		return []uint32{}, fmt.Errorf("failed to open counters map. err=%w", err)
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
		return []uint32{}, fmt.Errorf("failed to read counters map. err=%w", err)
	}

	bpfCounters := make([]uint32, MaxCounterNumber)
	for i := range bpfCounters {
		for cpu := 0; cpu < c.numOfCpu; cpu++ {
			begin := i*uint32Size + cpu*MaxCounterNumber*uint32Size
			data := uint32(binary.LittleEndian.Uint32(values[begin : begin+uint32Size]))
			bpfCounters[i] += data
		}
	}
	return bpfCounters, nil
}

func (c *Counters) Flush() error {
	for hook, name := range HooksName {
		err := c.flush(c.maps[hook])
		if err != nil {
			return fmt.Errorf("Failed to flush bpf counters for interface=%s hook=%s. err=%w", c.iface, name, err)
		}
		logrus.Infof("Successfully flushed counters map for interface=%s hook=%s", c.iface, name)
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
