// Copyright (c) 2016-2025 Tigera, Inc. All rights reserved.
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

package nfnetlink

import (
	"errors"

	"github.com/projectcalico/calico/felix/nfnetlink/nfnl"
)

const (
	DIR_IN = iota
	DIR_OUT
	__DIR_MAX
)

type CtCounters struct {
	Packets int
	Bytes   int
}

type CtL4Src struct {
	Port int // TCP, UDP
	Id   int // ICMP
	All  int // Others
}

type CtL4Dst struct {
	Port int // TCP, UDP
	Type int // ICMP
	Code int // ICMP
	All  int // Others
}

type CtTuple struct {
	Src        [16]byte
	Dst        [16]byte
	L3ProtoNum int
	ProtoNum   int
	Zone       int
	L4Src      CtL4Src
	L4Dst      CtL4Dst
}

var EmptyCtTuple = CtTuple{}

type CtProtoInfo struct {
	State int
}

type CtEntry struct {
	OriginalTuple CtTuple
	ReplyTuple    CtTuple
	Timeout       int
	Mark          int
	Secmark       int
	Status        int
	Use           int
	Id            int
	Zone          int

	OriginalCounters CtCounters
	ReplyCounters    CtCounters

	ProtoInfo CtProtoInfo
}

func (cte *CtEntry) IsNAT() bool {
	return cte.Status&nfnl.IPS_NAT_MASK != 0
}

func (cte *CtEntry) IsSNAT() bool {
	return cte.Status&nfnl.IPS_SRC_NAT != 0
}

func (cte *CtEntry) IsDNAT() bool {
	return cte.Status&nfnl.IPS_DST_NAT != 0
}

func (cte *CtEntry) OriginalTuplePostDNAT() (CtTuple, error) {
	if !cte.IsDNAT() {
		return EmptyCtTuple, errors.New("Entry is not DNAT-ed")
	}

	if cte.OriginalTuple.ProtoNum == nfnl.ICMP_PROTO {
		return CtTuple{
			cte.OriginalTuple.Src,
			cte.ReplyTuple.Src,
			cte.OriginalTuple.L3ProtoNum,
			cte.OriginalTuple.ProtoNum,
			cte.OriginalTuple.Zone,
			CtL4Src{Id: cte.ReplyTuple.L4Src.Id},
			CtL4Dst{Type: cte.ReplyTuple.L4Dst.Type, Code: cte.ReplyTuple.L4Dst.Code}}, nil
	} else if cte.OriginalTuple.ProtoNum == nfnl.TCP_PROTO || cte.OriginalTuple.ProtoNum == nfnl.UDP_PROTO {
		return CtTuple{
			cte.OriginalTuple.Src,
			cte.ReplyTuple.Src,
			cte.OriginalTuple.L3ProtoNum,
			cte.OriginalTuple.ProtoNum,
			cte.OriginalTuple.Zone,
			CtL4Src{Port: cte.ReplyTuple.L4Dst.Port},
			CtL4Dst{Port: cte.ReplyTuple.L4Src.Port}}, nil
	} else {
		return CtTuple{
			cte.OriginalTuple.Src,
			cte.ReplyTuple.Src,
			cte.OriginalTuple.L3ProtoNum,
			cte.OriginalTuple.ProtoNum,
			cte.OriginalTuple.Zone,
			CtL4Src{All: cte.ReplyTuple.L4Dst.All},
			CtL4Dst{All: cte.ReplyTuple.L4Src.All}}, nil
	}
}
