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
	"sort"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/bpf"
)

const (
	MaxCounterNumber    int = 14
	counterMapKeySize   int = 4
	counterMapValueSize int = 8
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

type Description struct {
	Category string
	Caption  string
	Counter  int
}

type DescList []Description

func (d DescList) Len() int {
	return len(d)
}

func (d DescList) Less(i, j int) bool {
	if d[i].Category == d[j].Category {
		return d[i].Caption < d[j].Caption
	}
	return d[i].Category < d[j].Category
}

func (d DescList) Swap(i, j int) {
	d[i], d[j] = d[j], d[i]
}

var descriptions DescList = DescList{
	{
		Counter:  TotalPackets,
		Category: "Total", Caption: "packets",
	},
	{
		Counter:  AcceptedByFailsafe,
		Category: "Accepted", Caption: "by failsafe",
	},
	{
		Counter:  AcceptedByPolicy,
		Category: "Accepted", Caption: "by policy",
	},
	{
		Counter:  AcceptedByAnotherProgram,
		Category: "Accepted", Caption: "by another program",
	},
	{
		Counter:  DroppedByPolicy,
		Category: "Dropped", Caption: "by policy",
	},
	{
		Counter:  DroppedShortPacket,
		Category: "Dropped", Caption: "too short packets",
	},
	{
		Counter:  DroppedFailedCSUM,
		Category: "Dropped", Caption: "incorrect checksum",
	},
	{
		Counter:  DroppedIPOptions,
		Category: "Dropped", Caption: "packets with unsupported IP options",
	},
	{
		Counter:  DroppredIPMalformed,
		Category: "Dropped", Caption: "malformed IP packets",
	},
	{
		Counter:  DroppedFailedEncap,
		Category: "Dropped", Caption: "failed encapsulation",
	},
	{
		Counter:  DroppedFailedDecap,
		Category: "Dropped", Caption: "failed decapsulation",
	},
	{
		Counter:  DroppedUnauthSource,
		Category: "Dropped", Caption: "packets with unknown source",
	},
	{
		Counter:  DroppedUnknownRoute,
		Category: "Dropped", Caption: "packets with unknown route",
	},
}

func Descriptions() DescList {
	sort.Stable(descriptions)
	return descriptions
}

type Counters struct {
	iface    string
	numOfCpu int
	maps     []bpf.Map
}

func NewCounters(iface string) *Counters {
	cntr := Counters{
		iface:    iface,
		numOfCpu: bpf.NumPossibleCPUs(),
		maps:     make([]bpf.Map, len(bpf.Hooks)),
	}

	for index, hook := range bpf.Hooks {
		pinPath := bpf.MapPinPath(unix.BPF_MAP_TYPE_PERCPU_ARRAY,
			bpf.CountersMapName(), iface, hook)
		cntr.maps[index] = Map(&bpf.MapContext{}, pinPath)
		logrus.Debugf("%s counter map pin path: %v", hook, pinPath)
	}

	return &cntr
}

func (c Counters) Read() ([][]uint64, error) {
	values := make([][]uint64, len(bpf.Hooks))
	for i := range values {
		values[i] = make([]uint64, MaxCounterNumber)
	}

	for hook, name := range bpf.Hooks {
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

func (c Counters) read(cMap bpf.Map) ([]uint64, error) {
	err := cMap.Open()
	if err != nil {
		return []uint64{}, fmt.Errorf("failed to open counters map. err=%w", err)
	}
	defer func() {
		err := cMap.Close()
		if err != nil {
			logrus.WithError(err).Errorf("failed to close counters map.")
		}
	}()

	// k is the key to the counters map, and it is set to 0 since there is only one entry
	k := make([]byte, counterMapKeySize)
	values, err := cMap.Get(k)
	if err != nil {
		return []uint64{}, fmt.Errorf("failed to read counters map. err=%w", err)
	}

	bpfCounters := make([]uint64, MaxCounterNumber)
	for i := range bpfCounters {
		for cpu := 0; cpu < c.numOfCpu; cpu++ {
			begin := i*counterMapValueSize + cpu*MaxCounterNumber*counterMapValueSize
			data := uint64(binary.LittleEndian.Uint32(values[begin : begin+counterMapValueSize]))
			bpfCounters[i] += data
		}
	}
	return bpfCounters, nil
}

func (c *Counters) Flush() error {
	for hook, name := range bpf.Hooks {
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
	k := make([]byte, counterMapKeySize)
	v := make([]byte, counterMapValueSize*MaxCounterNumber*c.numOfCpu)
	err = cMap.Update(k, v)
	if err != nil {
		return fmt.Errorf("failed to update counters map. err=%v", err)
	}
	return nil
}
