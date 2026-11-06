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
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/collector/types"
	"github.com/projectcalico/calico/felix/collector/types/tuple"
	"github.com/projectcalico/calico/felix/jitter"
	"github.com/projectcalico/calico/felix/nfnetlink"
	"github.com/projectcalico/calico/felix/nfnetlink/nfnl"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/lib/logrusr"
	"github.com/projectcalico/calico/libcalico-go/lib/health"
)

const defaultNFLOGRetryInterval = 5 * time.Second

type nflogAggregates = map[nfnetlink.NflogPacketTuple]*nfnetlink.NflogPacketAggregate

// nflogSubscribeFunc has the signature of nfnetlink.NflogSubscribe.
type nflogSubscribeFunc func(
	groupNum int, bufSize int, ch chan<- nflogAggregates, done <-chan struct{}, includeConnTrack bool,
) (<-chan error, error)

// NFLogReader consumes NFLog data and converts them to a format used by collector.  It keeps an
// NFLOG subscription running for each direction, resubscribing whenever one fails, and reports
// each as ready only while it is subscribed.
type NFLogReader struct {
	started  atomic.Bool
	stopOnce sync.Once
	wg       sync.WaitGroup
	stopC    chan struct{}

	luc              *calc.LookupsCache
	healthAggregator *health.HealthAggregator
	IngressC         chan nflogAggregates
	EgressC          chan nflogAggregates

	packetInfoC chan types.PacketInfo

	netlinkIngressGroup int
	netlinkEgressGroup  int
	bufSize             int
	servicesEnabled     bool

	subscribe     nflogSubscribeFunc
	retryInterval time.Duration
}

// NewNFLogReader creates an NFLogReader.  healthAggregator may be nil.
func NewNFLogReader(
	lookupsCache *calc.LookupsCache,
	healthAggregator *health.HealthAggregator,
	inGrp, eGrp, bufSize int,
	services bool,
) *NFLogReader {
	return &NFLogReader{
		stopC:            make(chan struct{}),
		luc:              lookupsCache,
		healthAggregator: healthAggregator,
		IngressC:         make(chan nflogAggregates, 1000),
		EgressC:          make(chan nflogAggregates, 1000),

		packetInfoC: make(chan types.PacketInfo, 1000),

		netlinkIngressGroup: inGrp,
		netlinkEgressGroup:  eGrp,
		bufSize:             bufSize,
		servicesEnabled:     services,

		subscribe:     nfnetlink.NflogSubscribe,
		retryInterval: defaultNFLOGRetryInterval,
	}
}

// Start starts the NFLOG subscriptions in the background.  An NFLogReader can only be started once.
func (r *NFLogReader) Start() error {
	if !r.started.CompareAndSwap(false, true) {
		return errors.New("NFLogReader can only be started once")
	}

	for _, sub := range []nflogSubscription{
		{direction: "ingress", healthName: "NFLOGIngressReader", groupNum: r.netlinkIngressGroup, ch: r.IngressC},
		{direction: "egress", healthName: "NFLOGEgressReader", groupNum: r.netlinkEgressGroup, ch: r.EgressC},
	} {
		if r.healthAggregator != nil {
			// Reporters start out not ready.
			r.healthAggregator.RegisterReporter(sub.healthName, &health.HealthReport{Ready: true}, 0)
		}
		r.wg.Go(func() {
			r.maintainSubscription(sub)
		})
	}
	r.wg.Go(func() {
		r.run()
	})

	return nil
}

// Stop stops the NFLOG subscriptions and waits for the reader's goroutines to exit.
func (r *NFLogReader) Stop() {
	r.stopOnce.Do(func() {
		close(r.stopC)
	})
	r.wg.Wait()
}

// Chan returns the channel with converted data structures
func (r *NFLogReader) PacketInfoChan() <-chan types.PacketInfo {
	return r.packetInfoC
}

type nflogSubscription struct {
	direction  string
	healthName string
	groupNum   int
	ch         chan nflogAggregates
}

// maintainSubscription subscribes to NFLOG until Stop, resubscribing retryInterval after each
// failure.
func (r *NFLogReader) maintainSubscription(sub nflogSubscription) {
	logCtx := log.WithFields(log.Fields{"direction": sub.direction, "groupNum": sub.groupNum})
	failureLog := logrusr.NewRateLimitedLogger(logrusr.OptInterval(time.Minute)).WithFields(logCtx.Data)
	for {
		err := r.runSubscription(sub, logCtx)
		r.reportReady(sub, false)
		if err == nil {
			// Stopped.
			return
		}
		failureLog.WithError(err).Error("NFLOG subscription failed, flow logs will lack policy " +
			"verdicts and rule hits until it recovers.  Will retry.")

		select {
		case <-r.stopC:
			return
		case <-time.After(r.retryInterval):
		}
	}
}

// runSubscription subscribes to NFLOG and blocks until the subscription ends.  It returns nil if it
// ended because of Stop.
func (r *NFLogReader) runSubscription(sub nflogSubscription, logCtx *log.Entry) error {
	endC, err := r.subscribe(sub.groupNum, r.bufSize, sub.ch, r.stopC, r.servicesEnabled)
	if err != nil {
		return fmt.Errorf("subscribing to NFLOG: %w", err)
	}
	logCtx.Info("Subscribed to NFLOG.")
	r.reportReady(sub, true)
	return <-endC
}

func (r *NFLogReader) reportReady(sub nflogSubscription, ready bool) {
	if r.healthAggregator == nil {
		return
	}
	r.healthAggregator.Report(sub.healthName, &health.HealthReport{Ready: ready})
}

func (r *NFLogReader) run() {
	for {
		select {
		case <-r.stopC:
			return
		case nflogPacketAggrMap := <-r.IngressC:
			if !r.sendPacketInfos(rules.RuleDirIngress, nflogPacketAggrMap) {
				return
			}
		case nflogPacketAggrMap := <-r.EgressC:
			if !r.sendPacketInfos(rules.RuleDirEgress, nflogPacketAggrMap) {
				return
			}
		}
	}
}

// sendPacketInfos converts the aggregates and sends them to packetInfoC.  It returns false if the
// reader was stopped first.
func (r *NFLogReader) sendPacketInfos(dir rules.RuleDir, aggrs nflogAggregates) bool {
	for _, nflogPacketAggr := range aggrs {
		select {
		case r.packetInfoC <- r.ConvertNflogPkt(dir, nflogPacketAggr):
		case <-r.stopC:
			return false
		}
	}
	return true
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
	r.wg.Go(func() {
		r.run()
	})
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
