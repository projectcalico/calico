// Copyright (c) 2020-2025 Tigera, Inc. All rights reserved.
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

package events

import (
	"net"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/projectcalico/calico/felix/bpf/state"
	"github.com/projectcalico/calico/felix/calc"
	collector "github.com/projectcalico/calico/felix/collector/types"
	"github.com/projectcalico/calico/felix/collector/types/tuple"
	"github.com/projectcalico/calico/felix/rules"
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

		pktInfo, ok := c.PacketInfo(e)
		if !ok {
			continue
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

// PacketInfo converts a policy verdict event into a PacketInfo holding the
// hits of the endpoint whose program sent the event.  It returns false if
// there are none whose direction it can tell.
//
// Flows are not reported against host endpoints, so it drops the hits of the
// transit policy (pre-DNAT and apply-on-forward) of the host endpoint that the
// program applies; otherwise they would be resolved against a workload's
// policy.  A workload's program can also apply host-*'s normal policy, ahead
// of the workload's own and in the opposite direction; it drops those hits
// too.
func (c *CollectorPolicyListener) PacketInfo(e PolicyVerdict) (collector.PacketInfo, bool) {
	numHits := min(int(e.RulesHit), state.MaxRuleIDs)
	transitHits := 0
	switch e.TransitPolicyHits {
	case state.TransitPolicyHitsUnknown:
		// A program from before Felix recorded transit_policy_hits; the
		// direction split below drops host-*'s hits in a workload's program.
	case state.TransitPolicyHitsAll:
		transitHits = numHits
	default:
		transitHits = min(int(e.TransitPolicyHits)-1, numHits)
	}

	// Take the direction from the last hit that resolves.  Earlier hits in the
	// opposite direction are host-*'s normal policy, applied ahead of a
	// workload's own.
	var rids [state.MaxRuleIDs]*calc.RuleID
	first, dirKnown := transitHits, false
	var dir rules.RuleDir
	for i := numHits - 1; i >= transitHits; i-- {
		rids[i] = c.lc.GetRuleIDFromID64(e.RuleIDs[i])
		if rids[i] == nil {
			continue
		}
		if !dirKnown {
			dir, dirKnown = rids[i].Direction, true
		} else if rids[i].Direction != dir {
			first = i + 1
			break
		}
	}
	if !dirKnown {
		return collector.PacketInfo{}, false
	}

	pktInfo := collector.PacketInfo{
		IsDNAT:    !e.DstAddr.Equal(e.PostNATDstAddr) || e.DstPort != e.PostNATDstPort,
		Tuple:     makeTuple(e.SrcAddr, e.PostNATDstAddr, e.IPProto, e.SrcPort, e.PostNATDstPort),
		Direction: dir,
		RuleHits:  make([]collector.RuleHit, 0, numHits-first),
	}
	if pktInfo.IsDNAT {
		pktInfo.PreDNATTuple = makeTuple(e.SrcAddr, e.DstAddr, e.IPProto, e.SrcPort, e.DstPort)
	}

	// Note, this is only relevant when we have just upgraded from older (pre v3.8) Felix code,
	// and the TC program has not yet been updated on all existing interfaces.
	// The pre v3.8 TC code does not report an actual size, and Felix userspace reports 1 instead.
	// TC program in v3.8 uses 2 bytes pad (memset to 0) in older versions to report IP length.
	// Thus, e.IPSize == 0 only matches older (pre v3.8) TC programs since IP header is at least 20 bytes.
	bytes := int(e.IPSize)
	if bytes == 0 {
		bytes = 1
	}
	for _, rid := range rids[first:numHits] {
		pktInfo.RuleHits = append(pktInfo.RuleHits, collector.RuleHit{RuleID: rid, Hits: 1, Bytes: bytes})
	}
	return pktInfo, true
}

// Stop stops the listener, mainly for testing purposes.
func (c *CollectorPolicyListener) Stop() {
	close(c.inC)
}

// PacketInfoChan provides the output channel with converted information.
func (c *CollectorPolicyListener) PacketInfoChan() <-chan collector.PacketInfo {
	return c.outC
}
