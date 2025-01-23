// Copyright (c) 2018-2025 Tigera, Inc. All rights reserved.
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

package collector

import (
	"fmt"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/collector/types/tuple"
	"github.com/projectcalico/calico/felix/rules"
)

// RuleHit records how many times a rule was hit and how many bytes passed
// through.
type RuleHit struct {
	RuleID *calc.RuleID
	Hits   int
	Bytes  int
}

// PacketInfo is information about a packet we received from the dataplane
type PacketInfo struct {
	Tuple        tuple.Tuple
	PreDNATTuple tuple.Tuple
	IsDNAT       bool
	Direction    rules.RuleDir
	RuleHits     []RuleHit
}

func (pkt PacketInfo) String() string {
	return fmt.Sprintf("Tuple: {%s}, PreDNATTuple: {%s}, IsDNAT: %t, Direction: %s, RuleHits: %+v",
		&pkt.Tuple, &pkt.PreDNATTuple, pkt.IsDNAT, pkt.Direction, pkt.RuleHits)
}

// PacketInfoReader is an interface for a reader that consumes information
// from dataplane and converts it to the format needed by colelctor
type PacketInfoReader interface {
	Start() error
	PacketInfoChan() <-chan PacketInfo
}

// ConntrackCounters counters for ConntrackInfo
type ConntrackCounters struct {
	Packets int
	Bytes   int
}

func (c ConntrackCounters) String() string {
	return fmt.Sprintf("Packets: %d, Bytes :%d", c.Packets, c.Bytes)
}

// ConntrackInfo is information about a connection from the dataplane.
type ConntrackInfo struct {
	Tuple           tuple.Tuple
	PreDNATTuple    tuple.Tuple
	NatOutgoingPort int
	IsDNAT          bool
	Expired         bool
	Counters        ConntrackCounters
	ReplyCounters   ConntrackCounters
}

func (ct ConntrackInfo) String() string {
	return fmt.Sprintf("Tuple: {%s}, PreDNATTuple: {%s}, IsDNAT: %t, Expired: %t, Counters: {%s}, ReplyCounters {%s}",
		&ct.Tuple, &ct.PreDNATTuple, ct.IsDNAT, ct.Expired, ct.Counters, ct.ReplyCounters)
}

// ConntrackInfoReader is an interafce that provides information from conntrack.
type ConntrackInfoReader interface {
	Start() error
	ConntrackInfoChan() <-chan []ConntrackInfo
}

// ConntrackInfoBatchSize is a recommended batch size to be used by InfoReaders
const ConntrackInfoBatchSize = 1024
