// Copyright (c) 2020-2023 Tigera, Inc. All rights reserved.

package events

import (
	"net"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/collector"
	"github.com/projectcalico/calico/felix/collector/types/tuple"
)

var (
	eventsCollectorBlocksCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_bpf_events_collector_blocks",
		Help: "CollectorPolicyListener blocks",
	})
)

func init() {
	prometheus.MustRegister(eventsCollectorBlocksCounter)
}

// CollectorPolicyListener is a backend plugin for the Collector to consume
// events from BPF policy programs and turn them into the common format.
type CollectorPolicyListener struct {
	lc   *calc.LookupsCache
	inC  chan PolicyVerdict
	outC chan collector.PacketInfo
}

// NewCollectorPolicyListener return a new instance of a CollectorPolicyListener.
func NewCollectorPolicyListener(lc *calc.LookupsCache) *CollectorPolicyListener {
	return &CollectorPolicyListener{
		lc:   lc,
		inC:  make(chan PolicyVerdict, 100),
		outC: make(chan collector.PacketInfo),
	}
}

// EventHandler can be registered as a sink/callback to consume the event.
func (c *CollectorPolicyListener) EventHandler(e Event) {
	var pv PolicyVerdict
	if e.Type() == TypePolicyVerdict {
		pv = ParsePolicyVerdict(e.Data(), false)
	} else if e.Type() == TypePolicyVerdictV6 {
		pv = ParsePolicyVerdict(e.Data(), true)
	}
	c.inC <- pv
}

// Start starts consuming events, converting and passong them to collector
func (c *CollectorPolicyListener) Start() error {
	go c.run()
	return nil
}

func makeTuple(src, dst net.IP, proto uint8, srcPort, dstPort uint16) tuple.Tuple {
	var src16, dst16 [16]byte
	copy(src16[:], src.To16())
	copy(dst16[:], dst.To16())
	return tuple.Make(src16, dst16, int(proto), int(srcPort), int(dstPort))
}

func (c *CollectorPolicyListener) run() {
	for {
		e, ok := <-c.inC

		if !ok {
			return
		}

		if e.RulesHit == 0 {
			// This should never happen, so just to be sure. We cannot determine
			// direction, skip it.
			continue
		}

		pktInfo := collector.PacketInfo{
			IsDNAT:   !e.DstAddr.Equal(e.PostNATDstAddr) || e.DstPort != e.PostNATDstPort,
			Tuple:    makeTuple(e.SrcAddr, e.PostNATDstAddr, e.IPProto, e.SrcPort, e.PostNATDstPort),
			RuleHits: make([]collector.RuleHit, e.RulesHit),
		}

		if pktInfo.IsDNAT {
			pktInfo.PreDNATTuple = makeTuple(e.SrcAddr, e.DstAddr, e.IPProto, e.SrcPort, e.DstPort)
		}

		for i := 0; i < int(e.RulesHit); i++ {
			id := e.RuleIDs[i]
			rid := c.lc.GetRuleIDFromID64(id)
			pktInfo.RuleHits[i] = collector.RuleHit{
				RuleID: rid,
				Hits:   1,
				Bytes:  int(e.IPSize),
			}

			// Note, this is only relevant when we have just upgraded from older (pre v3.8) Felix code,
			// and the TC program has not yet been updated on all existing interfaces.
			// The pre v3.8 TC code does not report an actual size, and Felix userspace reports 1 instead.
			// TC program in v3.8 uses 2 bytes pad (memset to 0) in older versions to report IP length.
			// Thus, e.IPSize == 0 only matches older (pre v3.8) TC programs since IP header is at least 20 bytes.
			if e.IPSize == 0 {
				pktInfo.RuleHits[i].Bytes = 1
			}

			// All directions should be the same
			if rid != nil {
				pktInfo.Direction = rid.Direction
			}
		}

		select {
		case c.outC <- pktInfo:
			// nothing, all good
		default:
			eventsCollectorBlocksCounter.Inc()
			c.outC <- pktInfo
		}
	}
}

// Stop stops the listener, mainly for testing purposes.
func (c *CollectorPolicyListener) Stop() {
	close(c.inC)
}

// PacketInfoChan provides the output channel with converted information.
func (c *CollectorPolicyListener) PacketInfoChan() <-chan collector.PacketInfo {
	return c.outC
}
