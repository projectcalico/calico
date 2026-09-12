// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package policyscale

import (
	"fmt"
	"math/rand"
	"net"
)

// The addresses and ports the denied flows use. TEST-NET addresses: generated IP set members and
// rule CIDRs all come from 10.0.0.0/8, so no rule matches them on address and the walk covers the
// whole policy set.
const (
	SourceIP     = "192.0.2.10"
	DeniedDestIP = "198.51.100.20"
	// UnlistedIP is in no generated set and no rule CIDR, and unlike the two above it is not in
	// the sentinel set either.
	UnlistedIP = "203.0.113.1"

	DefaultSourcePort = 45000
	// BaselineDestPort is the denied ingress flow's destination port; no baseline rule uses it.
	BaselineDestPort = 8080

	ProtocolTCP = 6
)

// Flow is an L4 flow with no L7 attributes, as the collector presents flows to the engine. It
// satisfies checker.Flow.
type Flow struct {
	SrcIP, DstIP     net.IP
	SrcPort, DstPort int
	Protocol         int
}

func (f *Flow) GetSourceIP() net.IP                { return f.SrcIP }
func (f *Flow) GetDestIP() net.IP                  { return f.DstIP }
func (f *Flow) GetSourcePort() int                 { return f.SrcPort }
func (f *Flow) GetDestPort() int                   { return f.DstPort }
func (f *Flow) GetProtocol() int                   { return f.Protocol }
func (f *Flow) GetHttpMethod() *string             { return nil }
func (f *Flow) GetHttpPath() *string               { return nil }
func (f *Flow) GetSourcePrincipal() *string        { return nil }
func (f *Flow) GetDestPrincipal() *string          { return nil }
func (f *Flow) GetSourceLabels() map[string]string { return nil }
func (f *Flow) GetDestLabels() map[string]string   { return nil }

func (f *Flow) String() string {
	return fmt.Sprintf("%d %s:%d->%s:%d", f.Protocol, f.SrcIP, f.SrcPort, f.DstIP, f.DstPort)
}

// NewFlow builds a TCP flow.
func NewFlow(srcIP string, srcPort int, dstIP string, dstPort int) *Flow {
	return &Flow{
		SrcIP:    net.ParseIP(srcIP),
		DstIP:    net.ParseIP(dstIP),
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Protocol: ProtocolTCP,
	}
}

// DeniedFlow returns a flow that no rule in the given direction matches, so an evaluation walks
// the whole policy set and ends in the tier default deny. In the egress direction it uses the most
// popular port, so that the address criteria of every rule sharing that port are evaluated too.
func (fx *Fixture) DeniedFlow(dir Direction) *Flow {
	port := BaselineDestPort
	if dir == Egress && fx.Spec.Egress != nil && len(fx.Spec.Egress.PortWeights) > 0 {
		port = int(fx.Spec.Egress.PortWeights[0].Port)
	}
	return NewFlow(SourceIP, DefaultSourcePort, DeniedDestIP, port)
}

// MatchingFlow returns a flow aimed at the rule at the given position of the walk in a direction:
// one that satisfies that rule's criteria. An earlier rule with overlapping criteria may match it
// first; Expect gives the actual verdict. A flow aimed at a rule that cannot match (an empty IP
// set, or a rule whose position is out of range) is a denied flow.
func (fx *Fixture) MatchingFlow(dir Direction, ordinal int) *Flow {
	f := fx.DeniedFlow(dir)
	_, r, ok := fx.ruleAt(dir, ordinal)
	if !ok {
		return f
	}
	if len(r.dstPorts) > 0 {
		f.DstPort = int(r.dstPorts[0])
	}
	switch {
	case r.dstNet.IsValid():
		f.DstIP = net.ParseIP(r.dstNet.Addr().Next().Next().String())
	case r.dstSet != "":
		f.DstIP = fx.addrMatching(r.dstSet)
	case r.srcSet != "":
		f.SrcIP = fx.addrMatching(r.srcSet)
	}
	return f
}

// addrMatching returns an address that satisfies a positive reference to the set: its first
// member, or, for a set the store does not hold (the engine skips those), an address outside the
// sentinel set. Nil when the set is present but empty, which no address satisfies.
func (fx *Fixture) addrMatching(setID string) net.IP {
	s := fx.sets[setID]
	if s.missing {
		return net.ParseIP(UnlistedIP)
	}
	if len(s.members) == 0 {
		return nil
	}
	ip, _, err := net.ParseCIDR(s.members[0])
	if err != nil {
		panic(err)
	}
	return ip
}

// FlowModel describes the mix of flows a Sampler produces.
type FlowModel struct {
	Direction Direction
	// MissFraction is the fraction of new flows that match no rule and walk the whole set.
	MissFraction float64
	// RepeatFraction is the fraction of flows that repeat an earlier flow's addresses and
	// destination port with a new source port, the way clients reconnect. It decides whether a
	// verdict cache keyed without the source port can help.
	RepeatFraction float64
	// RecentWindow is how many distinct flows repeats are drawn from. Default 1024.
	RecentWindow int
}

// Sampler produces flows following a FlowModel: matching flows are aimed uniformly at every depth
// of the walk, so the verdict mix follows the rule mix.
type Sampler struct {
	fx     *Fixture
	rng    *rand.Rand
	model  FlowModel
	recent []*Flow
}

// NewSampler returns a deterministic sampler for the fixture.
func (fx *Fixture) NewSampler(seed int64, model FlowModel) *Sampler {
	if model.RecentWindow <= 0 {
		model.RecentWindow = 1024
	}
	return &Sampler{fx: fx, rng: rand.New(rand.NewSource(seed)), model: model}
}

// Next returns the next flow. The returned flow is the caller's to keep.
func (s *Sampler) Next() *Flow {
	if len(s.recent) > 0 && s.rng.Float64() < s.model.RepeatFraction {
		f := *s.recent[s.rng.Intn(len(s.recent))]
		f.SrcPort = s.ephemeralPort()
		return &f
	}
	var f *Flow
	if rules := s.fx.Rules(s.model.Direction); rules == 0 || s.rng.Float64() < s.model.MissFraction {
		f = s.fx.DeniedFlow(s.model.Direction)
	} else {
		f = s.fx.MatchingFlow(s.model.Direction, s.rng.Intn(rules))
	}
	f.SrcPort = s.ephemeralPort()
	if len(s.recent) < s.model.RecentWindow {
		s.recent = append(s.recent, f)
	} else {
		s.recent[s.rng.Intn(len(s.recent))] = f
	}
	return f
}

func (s *Sampler) ephemeralPort() int {
	return 32768 + s.rng.Intn(28232)
}
