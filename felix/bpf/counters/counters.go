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

var (
	// zeroKey is the key to the counters map, and it is set to 0 as it has only one entry
	zeroKey = make([]byte, counterMapKeySize)
	zeroVal = make([]byte, counterMapValueSize*MaxCounterNumber*bpf.NumPossibleCPUs())
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

func (c Counters) Read(index int) ([]uint64, error) {
	err := c.maps[index].Open()
	if err != nil {
		return []uint64{}, fmt.Errorf("failed to open counters map. err=%w", err)
	}
	defer func() {
		err := c.maps[index].Close()
		if err != nil {
			logrus.WithError(err).Errorf("failed to close counters map.")
		}
	}()

	values, err := c.maps[index].Get(zeroKey)
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

func (c *Counters) Flush(index int) error {
	err := c.maps[index].Open()
	if err != nil {
		return fmt.Errorf("failed to open counters map. err=%v", err)
	}
	defer func() {
		err := c.maps[index].Close()
		if err != nil {
			logrus.WithError(err).Errorf("failed to close counters map.")
		}
	}()

	err = c.maps[index].Update(zeroKey, zeroVal)
	if err != nil {
		return fmt.Errorf("failed to update counters map. err=%v", err)
	}
	return nil
}
