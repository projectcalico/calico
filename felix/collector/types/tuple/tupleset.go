// Copyright (c) 2021-2023 Tigera, Inc. All rights reserved.

package tuple

import (
	"fmt"
	"net"
)

// Tuple represents a 5-Tuple value that identifies a connection/flow of packets
// with an implicit notion of Direction that comes with the use of a source and
// destination. This is a hashable object and can be used as a map's key.
type Tuple struct {
	Src   [16]byte
	Dst   [16]byte
	Proto int
	L4Src int
	L4Dst int
}

func New(src [16]byte, dst [16]byte, proto int, l4Src int, l4Dst int) *Tuple {
	t := Make(src, dst, proto, l4Src, l4Dst)
	return &t
}

func Make(src [16]byte, dst [16]byte, proto int, l4Src int, l4Dst int) Tuple {
	return Tuple{
		Src:   src,
		Dst:   dst,
		Proto: proto,
		L4Src: l4Src,
		L4Dst: l4Dst,
	}
}

func (t Tuple) String() string {
	return fmt.Sprintf("src=%v dst=%v proto=%v sport=%v dport=%v", net.IP(t.Src[:16]).String(), net.IP(t.Dst[:16]).String(), t.Proto, t.L4Src, t.L4Dst)
}

func (t Tuple) GetSourcePort() int {
	return t.L4Src
}

func (t Tuple) WithSourcePort(port int) Tuple {
	t.L4Src = port
	return t
}

func (t Tuple) GetDestPort() int {
	return t.L4Dst
}

func (t Tuple) SourceNet() net.IP {
	return net.IP(t.Src[:16])
}

func (t Tuple) DestNet() net.IP {
	return net.IP(t.Dst[:16])
}

// Reverse reverses the tuple by swapping the source and destination fields.
// This is *not* equivalent to the reply tuple and is intented as a convenience
// method only.
func (t Tuple) Reverse() Tuple {
	return Make(t.Dst, t.Src, t.Proto, t.L4Dst, t.L4Src)
}

type Set map[Tuple]int

func NewSet() Set {
	return make(Set)
}

func (set Set) Len() int {
	return len(set)
}

func (set Set) Add(t Tuple) {
	set[t] = 0
}

// AddWithValue assigns a value to the tuple key. This is useful for saving space when you need to store additional
// information on a tuple but you don't want to create another Tuple to value map in addition to this set. If a non
// empty value has been set for the Tuple key subsequent calls to change the value are ignored. This prevents updates
// that don't have the natOutgoingPort from removing the value.
//
// Note that the only information we currently want to store with a tuple is the post SNAT port. If we start storing
// more information then the value parameter should be changed to a more generic struct.
func (set Set) AddWithValue(t Tuple, natOutgoingPort int) {
	if set[t] == 0 {
		set[t] = natOutgoingPort
	}
}

func (set Set) Discard(t Tuple) {
	delete(set, t)
}

func (set Set) Contains(t Tuple) bool {
	_, present := set[t]
	return present
}

func (set Set) Copy() Set {
	ts := NewSet()
	for tuple, value := range set {
		ts.AddWithValue(tuple, value)
	}
	return ts
}
