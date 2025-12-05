//go:build linux

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
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/collector/types"
	"github.com/projectcalico/calico/felix/collector/types/tuple"
	"github.com/projectcalico/calico/felix/jitter"
	"github.com/projectcalico/calico/felix/nfnetlink"
	"github.com/projectcalico/calico/felix/nfnetlink/nfnl"
	"github.com/projectcalico/calico/felix/rules"
)

// NFLogReader consumes NFLog data and converts them to a format used by collector.
type NFLogReader struct {
	stopOnce sync.Once
	wg       sync.WaitGroup
	stopC    chan struct{}

	luc            *calc.LookupsCache
	IngressC       chan map[nfnetlink.NflogPacketTuple]*nfnetlink.NflogPacketAggregate
	EgressC        chan map[nfnetlink.NflogPacketTuple]*nfnetlink.NflogPacketAggregate
	nfIngressDoneC chan struct{}
	nfEgressDoneC  chan struct{}

	packetInfoC chan types.PacketInfo

	netlinkIngressGroup int
	netlinkEgressGroup  int
	bufSize             int
	servicesEnabled     bool
}

func NewNFLogReader(lookupsCache *calc.LookupsCache, inGrp, eGrp, bufSize int, services bool) *NFLogReader {
	return &NFLogReader{
		stopC:          make(chan struct{}),
		luc:            lookupsCache,
		IngressC:       make(chan map[nfnetlink.NflogPacketTuple]*nfnetlink.NflogPacketAggregate, 1000),
		EgressC:        make(chan map[nfnetlink.NflogPacketTuple]*nfnetlink.NflogPacketAggregate, 1000),
		nfIngressDoneC: make(chan struct{}),
		nfEgressDoneC:  make(chan struct{}),

		packetInfoC: make(chan types.PacketInfo, 1000),

		netlinkIngressGroup: inGrp,
		netlinkEgressGroup:  eGrp,
		bufSize:             bufSize,
		servicesEnabled:     services,
	}
}

func (r *NFLogReader) Start() error {
	if err := r.subscribe(); err != nil {
		return nil
	}

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.run()
	}()

	return nil
}

func (r *NFLogReader) Stop() {
	r.stopOnce.Do(func() {
		close(r.stopC)
	})
}

// Chan returns the channel with converted data structures
func (r *NFLogReader) PacketInfoChan() <-chan types.PacketInfo {
	return r.packetInfoC
}

func subscribeToNflog(gn int, nlBufSiz int, nflogChan chan map[nfnetlink.NflogPacketTuple]*nfnetlink.NflogPacketAggregate, nflogDoneChan chan struct{}, enableServices bool) error {
	return nfnetlink.NflogSubscribe(gn, nlBufSiz, nflogChan, nflogDoneChan, enableServices)
}

func (r *NFLogReader) subscribe() error {
	err := subscribeToNflog(r.netlinkIngressGroup, r.bufSize, r.IngressC, r.nfIngressDoneC, r.servicesEnabled)
	if err != nil {
		return fmt.Errorf("error when subscribing to NFLOG (ingress): %w", err)
	}

	err = subscribeToNflog(r.netlinkEgressGroup, r.bufSize, r.EgressC, r.nfEgressDoneC, r.servicesEnabled)
	if err != nil {
		return fmt.Errorf("error when subscribing to NFLOG (egress): %w", err)
	}

	return nil
}

func (r *NFLogReader) run() {
	for {
		select {
		case <-r.stopC:
			return
		case nflogPacketAggrMap := <-r.IngressC:
			for _, nflogPacketAggr := range nflogPacketAggrMap {
				info := r.ConvertNflogPkt(rules.RuleDirIngress, nflogPacketAggr)
				r.packetInfoC <- info
			}
		case nflogPacketAggrMap := <-r.EgressC:
			for _, nflogPacketAggr := range nflogPacketAggrMap {
				info := r.ConvertNflogPkt(rules.RuleDirEgress, nflogPacketAggr)
				r.packetInfoC <- info
			}
		}
	}
}

func (r *NFLogReader) ConvertNflogPkt(dir rules.RuleDir, nPktAggr *nfnetlink.NflogPacketAggregate) types.PacketInfo {
	info := types.PacketInfo{
		Direction: dir,
		RuleHits:  make([]types.RuleHit, 0, len(nPktAggr.Prefixes)),
	}

	info.Tuple = extractTupleFromNflogTuple(nPktAggr.Tuple)
	if nPktAggr.IsDNAT {
		info.IsDNAT = true
		info.PreDNATTuple = extractTupleFromCtEntryTuple(nPktAggr.OriginalTuple)
	}

	for _, prefix := range nPktAggr.Prefixes {
		ruleID := r.luc.GetRuleIDFromNFLOGPrefix(prefix.Prefix)
		if ruleID == nil {
			continue
		}

		info.RuleHits = append(info.RuleHits, types.RuleHit{
			RuleID: ruleID,
			Hits:   prefix.Packets,
			Bytes:  prefix.Bytes,
		})
	}

	return info
}

func ConvertCtEntryToConntrackInfo(ctEntry nfnetlink.CtEntry) (types.ConntrackInfo, error) {
	var (
		ctTuple nfnetlink.CtTuple
		err     error
	)

	ctTuple = ctEntry.OriginalTuple

	// A conntrack entry that has the destination NAT (DNAT) flag set
	// will have its destination ip-address set to the NAT-ed IP rather
	// than the actual workload/host endpoint. To continue processing
	// this conntrack entry, we need the actual IP address that corresponds
	// to a Workload/Host Endpoint.
	if ctEntry.IsDNAT() {
		ctTuple, err = ctEntry.OriginalTuplePostDNAT()
		if err != nil {
			return types.ConntrackInfo{}, fmt.Errorf("error when extracting tuple without DNAT: %w", err)
		}
	}

	// At this point either the source or destination IP address from the conntrack entry
	// belongs to an endpoint i.e., the connection either begins or terminates locally.
	tuple := extractTupleFromCtEntryTuple(ctTuple)

	// In the case of TCP, check if we can expire the entry early. We try to expire
	// entries early so that we don't send any spurious MetricUpdates for an expiring
	// conntrack entry.
	entryExpired := (ctTuple.ProtoNum == nfnl.TCP_PROTO && ctEntry.ProtoInfo.State >= nfnl.TCP_CONNTRACK_TIME_WAIT)

	var natOutgoingPort int
	// Keep track of the nat outgoing port if the packet was SNAT'd and the source and post DNAT destination aren't the
	// same (if they're the same it means the source opened a connection with itself via a service, so the packet didn't
	// leave the node).
	if ctEntry.IsSNAT() && tuple.Src != tuple.Dst {
		natOutgoingPort = ctEntry.ReplyTuple.L4Dst.Port
	}

	ctInfo := types.ConntrackInfo{
		Tuple:           tuple,
		NatOutgoingPort: natOutgoingPort,
		Expired:         entryExpired,
		Counters: types.ConntrackCounters{
			Packets: ctEntry.OriginalCounters.Packets,
			Bytes:   ctEntry.OriginalCounters.Bytes,
		},
		ReplyCounters: types.ConntrackCounters{
			Packets: ctEntry.ReplyCounters.Packets,
			Bytes:   ctEntry.ReplyCounters.Bytes,
		},
	}

	if ctEntry.IsDNAT() {
		ctInfo.IsDNAT = true
		ctInfo.PreDNATTuple = extractTupleFromCtEntryTuple(ctEntry.OriginalTuple)
	}

	return ctInfo, nil
}

// NetLinkConntrackReader reads connrack information from Linux via netlink.
type NetLinkConntrackReader struct {
	stopOnce sync.Once
	wg       sync.WaitGroup
	stopC    chan struct{}

	ticker jitter.TickerInterface
	outC   chan []types.ConntrackInfo
}

// NewNetLinkConntrackReader returns a new NetLinkConntrackReader
func NewNetLinkConntrackReader(period time.Duration) *NetLinkConntrackReader {
	return &NetLinkConntrackReader{
		stopC:  make(chan struct{}),
		ticker: jitter.NewTicker(period, period/10),
		outC:   make(chan []types.ConntrackInfo, 1000),
	}
}

func (r *NetLinkConntrackReader) Start() error {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.run()
	}()
	return nil
}

func (r *NetLinkConntrackReader) Stop() {
	r.stopOnce.Do(func() {
		close(r.stopC)
		r.ticker.Stop()
	})
}

func (r *NetLinkConntrackReader) run() {
	for {
		select {
		case <-r.stopC:
			return
		case <-r.ticker.Channel():
			ctInfos := make([]types.ConntrackInfo, 0, types.ConntrackInfoBatchSize)
			_ = nfnetlink.ConntrackList(func(ctEntry nfnetlink.CtEntry) {
				ci, err := ConvertCtEntryToConntrackInfo(ctEntry)
				if err != nil {
					log.Error(err.Error())
					return
				}
				ctInfos = append(ctInfos, ci)
				if len(ctInfos) > types.ConntrackInfoBatchSize {
					select {
					case <-r.stopC:
						return
					case r.outC <- ctInfos:
						ctInfos = make([]types.ConntrackInfo, 0, types.ConntrackInfoBatchSize)
					default:
						// Keep buffering
					}
				}
			})
			if len(ctInfos) > 0 {
				select {
				case <-r.stopC:
					return
				case r.outC <- ctInfos:
				}
			}
		}
	}
}

func (r *NetLinkConntrackReader) ConntrackInfoChan() <-chan []types.ConntrackInfo {
	return r.outC
}

func extractTupleFromNflogTuple(nflogTuple nfnetlink.NflogPacketTuple) tuple.Tuple {
	var l4Src, l4Dst int
	if nflogTuple.Proto == 1 {
		l4Src = nflogTuple.L4Src.Id
		l4Dst = int(uint16(nflogTuple.L4Dst.Type)<<8 | uint16(nflogTuple.L4Dst.Code))
	} else {
		l4Src = nflogTuple.L4Src.Port
		l4Dst = nflogTuple.L4Dst.Port
	}
	return tuple.Make(nflogTuple.Src, nflogTuple.Dst, nflogTuple.Proto, l4Src, l4Dst)
}

func extractTupleFromCtEntryTuple(ctTuple nfnetlink.CtTuple) tuple.Tuple {
	var l4Src, l4Dst int
	if ctTuple.ProtoNum == 1 {
		l4Src = ctTuple.L4Src.Id
		l4Dst = int(uint16(ctTuple.L4Dst.Type)<<8 | uint16(ctTuple.L4Dst.Code))
	} else {
		l4Src = ctTuple.L4Src.Port
		l4Dst = ctTuple.L4Dst.Port
	}
	return tuple.Make(ctTuple.Src, ctTuple.Dst, ctTuple.ProtoNum, l4Src, l4Dst)
}
