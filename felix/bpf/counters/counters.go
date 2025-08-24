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
	"os"
	"sort"

	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/bpf/hook"
	"github.com/projectcalico/calico/felix/bpf/maps"
)

const (
	MaxCounterNumber    int = 24
	counterMapKeySize   int = 8
	counterMapValueSize int = 8
)

var (
	zeroVal = make([]byte, counterMapValueSize*MaxCounterNumber*maps.NumPossibleCPUs())
)

type Key [8]byte

func (k Key) AsBytes() []byte {
	return k[:]
}

func NewKey(ifindex int, hook hook.Hook) Key {
	var k Key

	binary.LittleEndian.PutUint32(k[:4], uint32(ifindex))
	binary.LittleEndian.PutUint32(k[4:8], uint32(hook))

	return k

}

func (k Key) IfIndex() int {
	return int(binary.LittleEndian.Uint32(k[:4]))
}

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
	DroppedIPMalformed
	DroppedFailedEncap
	DroppedFailedDecap
	DroppedUnauthSource
	DroppedUnknownRoute
	DroppedBlackholeRoute
	SourceCollisionHit
	SourceCollisionResolutionFailed
	ConntrackCreateFailed
	Redirect
	RedirectNeigh
	RedirectPeer
	DroppedFragWait
	DroppedFragReorder
	DroppedFragUnsupported
	DroppedQoS
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
		Counter:  DroppedIPMalformed,
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
	{
		Counter:  DroppedBlackholeRoute,
		Category: "Dropped", Caption: "packets hitting blackhole route",
	},
	{
		Counter:  SourceCollisionHit,
		Category: "Other", Caption: "packets hitting NAT source collision",
	},
	{
		Counter:  ConntrackCreateFailed,
		Category: "Dropped", Caption: "failed to create conntrack",
	},
	{
		Counter:  SourceCollisionResolutionFailed,
		Category: "Dropped", Caption: "NAT source collision resolution failed",
	},
	{
		Counter:  Redirect,
		Category: "Redirect", Caption: "plain",
	},
	{
		Counter:  RedirectNeigh,
		Category: "Redirect", Caption: "neigh",
	},
	{
		Counter:  RedirectPeer,
		Category: "Redirect", Caption: "peer",
	},
	{
		Counter:  DroppedFragWait,
		Category: "Dropped", Caption: "fragment of yet incomplete packet",
	},
	{
		Counter:  DroppedFragReorder,
		Category: "Dropped", Caption: "fragment out of order within host",
	},
	{
		Counter:  DroppedFragUnsupported,
		Category: "Dropped", Caption: "fragments not supported",
	},
	{
		Counter:  DroppedQoS,
		Category: "Dropped", Caption: "QoS control limit",
	},
}

func Descriptions() DescList {
	sort.Stable(descriptions)
	return descriptions
}

func Read(m maps.Map, ifindex int, hook hook.Hook) ([]uint64, error) {
	values, err := m.Get(NewKey(ifindex, hook).AsBytes())
	if err != nil {
		return []uint64{}, fmt.Errorf("failed to read counters map. err=%w", err)
	}

	bpfCounters := make([]uint64, MaxCounterNumber)
	for i := range bpfCounters {
		for cpu := 0; cpu < maps.NumPossibleCPUs(); cpu++ {
			begin := i*counterMapValueSize + cpu*MaxCounterNumber*counterMapValueSize
			data := uint64(binary.LittleEndian.Uint32(values[begin : begin+counterMapValueSize]))
			bpfCounters[i] += data
		}
	}
	return bpfCounters, nil
}

func Flush(m maps.Map, ifindex int, hook hook.Hook) error {
	if err := m.(maps.MapWithUpdateWithFlags).
		UpdateWithFlags(NewKey(ifindex, hook).AsBytes(), zeroVal, unix.BPF_EXIST); err != nil {
		return fmt.Errorf("failed to update counters map. err=%v", err)
	}
	return nil
}

func EnsureExists(m maps.Map, ifindex int, hook hook.Hook) error {
	err := m.(maps.MapWithUpdateWithFlags).
		UpdateWithFlags(NewKey(ifindex, hook).AsBytes(), zeroVal, unix.BPF_NOEXIST)
	if err != nil && !os.IsExist(err) {
		return fmt.Errorf("failed to create zero counters for ifindex %d hook %s. err=%v", ifindex, hook, err)
	}
	return nil
}
