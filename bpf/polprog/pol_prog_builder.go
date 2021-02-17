// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

package polprog

import (
	"fmt"
	"math"
	"math/bits"
	"strings"

	"github.com/projectcalico/felix/bpf/ipsets"

	"github.com/projectcalico/felix/bpf"

	log "github.com/sirupsen/logrus"

	. "github.com/projectcalico/felix/bpf/asm"
	"github.com/projectcalico/felix/ip"
	"github.com/projectcalico/felix/proto"
	"github.com/projectcalico/felix/rules"
)

type Builder struct {
	b               *Block
	ruleID          int
	rulePartID      int
	ipSetIDProvider ipSetIDProvider

	ipSetMapFD bpf.MapFD
	stateMapFD bpf.MapFD
	jumpMapFD  bpf.MapFD
}

type ipSetIDProvider interface {
	GetNoAlloc(ipSetID string) uint64
}

func NewBuilder(ipSetIDProvider ipSetIDProvider, ipsetMapFD, stateMapFD, jumpMapFD bpf.MapFD) *Builder {
	b := &Builder{
		ipSetIDProvider: ipSetIDProvider,
		ipSetMapFD:      ipsetMapFD,
		stateMapFD:      stateMapFD,
		jumpMapFD:       jumpMapFD,
	}
	return b
}

var offset int = 0

func nextOffset(size int, align int) int16 {
	offset -= size
	remainder := offset % align
	if remainder != 0 {
		// For negative numbers, the remainder is negative (e.g. -9 % 8 == -1)
		offset = offset - remainder - align
	}
	return int16(offset)
}

var (
	// Stack offsets.  These are defined locally.
	offStateKey    = nextOffset(4, 4)
	offSrcIPSetKey = nextOffset(ipsets.IPSetEntrySize, 8)
	offDstIPSetKey = nextOffset(ipsets.IPSetEntrySize, 8)

	// Offsets within the cal_tc_state struct.
	// WARNING: must be kept in sync with the definitions in bpf/include/jump.h.
	stateOffIPSrc          int16 = 0
	stateOffIPDst          int16 = 4
	_                            = stateOffIPDst
	stateOffPostNATIPDst   int16 = 8
	stateOffPolResult      int16 = 16
	stateOffSrcPort        int16 = 20
	stateOffDstPort        int16 = 22
	stateOffICMPType       int16 = 22
	_                            = stateOffDstPort
	stateOffPostNATDstPort int16 = 24
	stateOffIPProto        int16 = 26

	// Compile-time check that IPSetEntrySize hasn't changed; if it changes, the code will need to change.
	_ = [1]struct{}{{}}[20-ipsets.IPSetEntrySize]

	// Offsets within struct ip4_set_key.
	// WARNING: must be kept in sync with the definitions in bpf/ipsets/map.go.
	// WARNING: must be kept in sync with the definitions in bpf/include/policy.h.
	ipsKeyPrefix int16 = 0
	ipsKeyID     int16 = 4
	ipsKeyAddr   int16 = 12
	ipsKeyPort   int16 = 16
	ipsKeyProto  int16 = 18
	ipsKeyPad    int16 = 19
)

func (p *Builder) Instructions(rules [][][]*proto.Rule) (Insns, error) {
	p.b = NewBlock()
	p.writeProgramHeader()
	p.writeRules(rules)
	p.writeProgramFooter()
	return p.b.Assemble()
}

// writeProgramHeader emits instructions to load the state from the state map, leaving
// R6 = program context
// R9 = pointer to state map
func (p *Builder) writeProgramHeader() {
	// Pre-amble to the policy program.
	p.b.LabelNextInsn("start")
	p.b.Mov64(R6, R1) // Save R1 (context) in R6.
	// Zero-out the map key
	p.b.MovImm64(R1, 0) // R1 = 0
	p.b.StoreStack32(R1, offStateKey)
	// Get pointer to map key in R2.
	p.b.Mov64(R2, R10) // R2 = R10
	p.b.AddImm64(R2, int32(offStateKey))
	// Load map file descriptor into R1.
	// clang uses a 64-bit load so copy that for now.
	p.b.LoadMapFD(R1, uint32(p.stateMapFD)) // R1 = 0 (64-bit immediate)
	p.b.Call(HelperMapLookupElem)           // Call helper
	// Check return value for NULL.
	p.b.JumpEqImm64(R0, 0, "deny")
	// Save state pointer in R9.
	p.b.Mov64(R9, R0)
	p.b.LabelNextInsn("policy")
}

const (
	jumpIdxPolicy = iota
	jumpIdxEpilogue
	_ = jumpIdxPolicy
)

const (
	PolRCNoMatch                = 0
	PolRCAllow                  = 1
	PolRCDeny                   = 2
	PolRCEpilogueTailCallFailed = 10
)

// writeProgramFooter emits the program exit jump targets.
func (p *Builder) writeProgramFooter() {
	// Fall through here if there's no match.  Also used when we hit an error or if policy rejects packet.
	p.b.LabelNextInsn("deny")
	p.b.MovImm64(R0, 2 /* TC_ACT_SHOT */)
	p.b.Exit()

	if p.b.TargetIsUsed("allow") {
		p.b.LabelNextInsn("allow")
		// Store the policy result in the state for the next program to see.
		p.b.MovImm32(R1, 1)
		p.b.Store32(R9, R1, stateOffPolResult)
		// Execute the tail call.
		p.b.Mov64(R1, R6)                      // First arg is the context.
		p.b.LoadMapFD(R2, uint32(p.jumpMapFD)) // Second arg is the map.
		p.b.MovImm32(R3, jumpIdxEpilogue)      // Third arg is the index (rather than a pointer to the index).
		p.b.Call(HelperTailCall)

		// Fall through if tail call fails.
		p.b.MovImm32(R1, PolRCEpilogueTailCallFailed)
		p.b.Store32(R9, R1, stateOffPolResult)
		p.b.MovImm64(R0, 2 /* TC_ACT_SHOT */)
		p.b.Exit()
	}
}

func (p *Builder) setUpSrcIPSetKey(ipsetID uint64) {
	p.setUpIPSetKey(ipsetID, offSrcIPSetKey, stateOffIPSrc, stateOffSrcPort)
}

func (p *Builder) setUpDstIPSetKey(ipsetID uint64) {
	p.setUpIPSetKey(ipsetID, offDstIPSetKey, stateOffPostNATIPDst, stateOffPostNATDstPort)
}

func (p *Builder) setUpIPSetKey(ipsetID uint64, keyOffset, ipOffset, portOffset int16) {
	// TODO track whether we've already done an initialisation and skip the parts that don't change.
	// Zero the padding.
	p.b.MovImm64(R1, 0) // R1 = 0
	p.b.StoreStack8(R1, keyOffset+ipsKeyPad)
	p.b.MovImm64(R1, 128) // R1 = 128
	p.b.StoreStack32(R1, keyOffset+ipsKeyPrefix)

	// Store the IP address, port and protocol.
	p.b.Load32(R1, R9, ipOffset)
	p.b.StoreStack32(R1, keyOffset+ipsKeyAddr)
	p.b.Load16(R1, R9, portOffset)
	p.b.StoreStack16(R1, keyOffset+ipsKeyPort)
	p.b.Load8(R1, R9, stateOffIPProto)
	p.b.StoreStack8(R1, keyOffset+ipsKeyProto)

	// Store the IP set ID.  It is 64-bit but, since it's a packed struct, we have to write it in two
	// 32-bit chunks.
	beIPSetID := bits.ReverseBytes64(ipsetID)
	p.b.MovImm32(R1, int32(beIPSetID))
	p.b.StoreStack32(R1, keyOffset+ipsKeyID)
	p.b.MovImm32(R1, int32(beIPSetID>>32))
	p.b.StoreStack32(R1, keyOffset+ipsKeyID+4)
}

func (p *Builder) writeRules(rules [][][]*proto.Rule) {
	for polOrProfIdx, polsOrProfs := range rules {
		endOfTierLabel := fmt.Sprint("end_of_tier_", polOrProfIdx)

		log.Debugf("Start of policies or profiles %d", polOrProfIdx)
		for polIdx, pol := range polsOrProfs {
			log.Debugf("Start of policy/profile %d", polIdx)
			for ruleIdx, rule := range pol {
				log.Debugf("Start of rule %d", ruleIdx)
				action := strings.ToLower(rule.Action)
				if action == "log" {
					log.Debug("Skipping log rule.  Not supported in BPF mode.")
					continue
				}
				p.writeRule(rule, endOfTierLabel)
				log.Debugf("End of rule %d", ruleIdx)
			}
			log.Debugf("End of policy/profile %d", polIdx)
		}

		// End of polsOrProfs drop rule.
		log.Debugf("End of policies/profiles drop")
		p.writeRule(&proto.Rule{Action: "deny"}, endOfTierLabel)

		p.b.LabelNextInsn(endOfTierLabel)
	}
}

type matchLeg string

const (
	legSource matchLeg = "source"
	legDest   matchLeg = "dest"
)

func (p *Builder) writeRule(rule *proto.Rule, passLabel string) {

	rule = rules.FilterRuleToIPVersion(4, rule)
	if rule == nil {
		log.Debugf("Version mismatch, skipping rule")
		return
	}
	p.writeStartOfRule()

	if rule.Protocol != nil {
		log.WithField("proto", rule.Protocol).Debugf("Protocol match")
		p.writeProtoMatch(false, rule.Protocol)
	}
	if rule.NotProtocol != nil {
		log.WithField("proto", rule.NotProtocol).Debugf("NotProtocol match")
		p.writeProtoMatch(true, rule.NotProtocol)
	}

	if len(rule.SrcNet) != 0 {
		log.WithField("cidrs", rule.SrcNet).Debugf("SrcNet match")
		p.writeCIDRSMatch(false, legSource, rule.SrcNet)
	}
	if len(rule.NotSrcNet) != 0 {
		log.WithField("cidrs", rule.NotSrcNet).Debugf("NotSrcNet match")
		p.writeCIDRSMatch(true, legSource, rule.NotSrcNet)
	}

	if len(rule.DstNet) != 0 {
		log.WithField("cidrs", rule.DstNet).Debugf("DstNet match")
		p.writeCIDRSMatch(false, legDest, rule.DstNet)
	}
	if len(rule.NotDstNet) != 0 {
		log.WithField("cidrs", rule.NotDstNet).Debugf("NotDstNet match")
		p.writeCIDRSMatch(true, legDest, rule.NotDstNet)
	}

	if len(rule.SrcIpSetIds) > 0 {
		log.WithField("ipSetIDs", rule.SrcIpSetIds).Debugf("SrcIpSetIds match")
		p.writeIPSetMatch(false, legSource, rule.SrcIpSetIds)
	}
	if len(rule.NotSrcIpSetIds) > 0 {
		log.WithField("ipSetIDs", rule.NotSrcIpSetIds).Debugf("NotSrcIpSetIds match")
		p.writeIPSetMatch(true, legSource, rule.NotSrcIpSetIds)
	}

	if len(rule.DstIpSetIds) > 0 {
		log.WithField("ipSetIDs", rule.DstIpSetIds).Debugf("DstIpSetIds match")
		p.writeIPSetMatch(false, legDest, rule.DstIpSetIds)
	}
	if len(rule.NotDstIpSetIds) > 0 {
		log.WithField("ipSetIDs", rule.NotDstIpSetIds).Debugf("NotDstIpSetIds match")
		p.writeIPSetMatch(true, legDest, rule.NotDstIpSetIds)
	}

	if len(rule.SrcPorts) > 0 || len(rule.SrcNamedPortIpSetIds) > 0 {
		log.WithField("ports", rule.SrcPorts).Debugf("SrcPorts match")
		p.writePortsMatch(false, legSource, rule.SrcPorts, rule.SrcNamedPortIpSetIds)
	}
	if len(rule.NotSrcPorts) > 0 || len(rule.NotSrcNamedPortIpSetIds) > 0 {
		log.WithField("ports", rule.NotSrcPorts).Debugf("NotSrcPorts match")
		p.writePortsMatch(true, legSource, rule.NotSrcPorts, rule.NotSrcNamedPortIpSetIds)
	}

	if len(rule.DstPorts) > 0 || len(rule.DstNamedPortIpSetIds) > 0 {
		log.WithField("ports", rule.DstPorts).Debugf("DstPorts match")
		p.writePortsMatch(false, legDest, rule.DstPorts, rule.DstNamedPortIpSetIds)
	}
	if len(rule.NotDstPorts) > 0 || len(rule.NotDstNamedPortIpSetIds) > 0 {
		log.WithField("ports", rule.NotDstPorts).Debugf("NotDstPorts match")
		p.writePortsMatch(true, legDest, rule.NotDstPorts, rule.NotDstNamedPortIpSetIds)
	}

	if rule.Icmp != nil {
		log.WithField("icmpv4", rule.Icmp).Debugf("ICMP type/code match")
		switch icmp := rule.Icmp.(type) {
		case *proto.Rule_IcmpTypeCode:
			p.writeICMPTypeCodeMatch(false, uint8(icmp.IcmpTypeCode.Type), uint8(icmp.IcmpTypeCode.Code))
		case *proto.Rule_IcmpType:
			p.writeICMPTypeMatch(false, uint8(icmp.IcmpType))
		}
	}
	if rule.NotIcmp != nil {
		log.WithField("icmpv4", rule.Icmp).Debugf("Not ICMP type/code match")
		switch icmp := rule.NotIcmp.(type) {
		case *proto.Rule_NotIcmpTypeCode:
			p.writeICMPTypeCodeMatch(true, uint8(icmp.NotIcmpTypeCode.Type), uint8(icmp.NotIcmpTypeCode.Code))
		case *proto.Rule_NotIcmpType:
			p.writeICMPTypeMatch(true, uint8(icmp.NotIcmpType))
		}
	}

	p.writeEndOfRule(rule, passLabel)
	p.ruleID++
	p.rulePartID = 0
}

func (p *Builder) writeStartOfRule() {
}

func (p *Builder) writeEndOfRule(rule *proto.Rule, passLabel string) {
	// If all the match criteria are mat, we fall through to the end of the rule
	// so all that's left to do is to jump to the relevant action.
	// TODO log and log-and-xxx actions
	action := strings.ToLower(rule.Action)
	if action == "pass" {
		action = passLabel
	}
	p.b.Jump(action)

	p.b.LabelNextInsn(p.endOfRuleLabel())
}

func (p *Builder) writeProtoMatch(negate bool, protocol *proto.Protocol) {
	p.b.Load8(R1, R9, stateOffIPProto)
	protoNum := protocolToNumber(protocol)
	if negate {
		p.b.JumpEqImm64(R1, int32(protoNum), p.endOfRuleLabel())
	} else {
		p.b.JumpNEImm64(R1, int32(protoNum), p.endOfRuleLabel())
	}
}

func (p *Builder) writeICMPTypeMatch(negate bool, icmpType uint8) {
	p.b.Load8(R1, R9, stateOffICMPType)
	if negate {
		p.b.JumpEqImm64(R1, int32(icmpType), p.endOfRuleLabel())
	} else {
		p.b.JumpNEImm64(R1, int32(icmpType), p.endOfRuleLabel())
	}
}

func (p *Builder) writeICMPTypeCodeMatch(negate bool, icmpType, icmpCode uint8) {
	p.b.Load16(R1, R9, stateOffICMPType)
	if negate {
		p.b.JumpEqImm64(R1, ((int32(icmpCode) << 8) | int32(icmpType)), p.endOfRuleLabel())
	} else {
		p.b.JumpNEImm64(R1, ((int32(icmpCode) << 8) | int32(icmpType)), p.endOfRuleLabel())
	}
}
func (p *Builder) writeCIDRSMatch(negate bool, leg matchLeg, cidrs []string) {
	var offset int16
	if leg == legSource {
		offset = stateOffIPSrc
	} else {
		offset = stateOffPostNATIPDst
	}

	p.b.Load32(R1, R9, offset)

	var onMatchLabel string
	if negate {
		// Match negated, if we match any CIDR then we jump to the next rule.
		onMatchLabel = p.endOfRuleLabel()
	} else {
		// Match is non-negated, if we match, got to the next match criteria.
		onMatchLabel = p.freshPerRuleLabel()
	}
	for _, cidrStr := range cidrs {
		cidr := ip.MustParseCIDROrIP(cidrStr)
		addrU32 := bits.ReverseBytes32(cidr.Addr().(ip.V4Addr).AsUint32()) // TODO IPv6
		maskU32 := bits.ReverseBytes32(math.MaxUint32 << (32 - cidr.Prefix()) & math.MaxUint32)

		p.b.MovImm32(R2, int32(maskU32))
		p.b.And32(R2, R1)
		p.b.JumpEqImm32(R2, int32(addrU32), onMatchLabel)
	}
	if !negate {
		// If we fall through then none of the CIDRs matched so the rule doesn't match.
		p.b.Jump(p.endOfRuleLabel())
		// Label the next match so we can skip to it on success.
		p.b.LabelNextInsn(onMatchLabel)
	}
}

func (p *Builder) writeIPSetMatch(negate bool, leg matchLeg, ipSets []string) {
	// IP sets are different to CIDRs, if we have multiple IP sets then they all have to match
	// so we treat them as independent match criteria.
	for _, ipSetID := range ipSets {
		id := p.ipSetIDProvider.GetNoAlloc(ipSetID)
		if id == 0 {
			log.WithField("setID", ipSetID).Panic("Failed to look up IP set ID.")
		}

		var keyOffset int16
		if leg == legSource {
			p.setUpSrcIPSetKey(id)
			keyOffset = offSrcIPSetKey
		} else {
			p.setUpDstIPSetKey(id)
			keyOffset = offDstIPSetKey
		}

		p.b.LoadMapFD(R1, uint32(p.ipSetMapFD))
		p.b.Mov64(R2, R10)
		p.b.AddImm64(R2, int32(keyOffset))
		p.b.Call(HelperMapLookupElem)

		if negate {
			// Negated; if we got a hit (non-0) then the rule doesn't match.
			// (Otherwise we fall through to the next match criteria.)
			p.b.JumpNEImm64(R0, 0, p.endOfRuleLabel())
		} else {
			// Non-negated; if we got a miss (non-0) then the rule can't match.
			// (Otherwise we fall through to the next match criteria.)
			p.b.JumpEqImm64(R0, 0, p.endOfRuleLabel())
		}
	}
}

func (p *Builder) writePortsMatch(negate bool, leg matchLeg, ports []*proto.PortRange, namedPorts []string) {
	// For a ports match, numeric ports and named ports are ORed together.  Check any
	// numeric ports first and then any named ports.
	var portOffset int16
	if leg == legSource {
		portOffset = stateOffSrcPort
	} else {
		portOffset = stateOffPostNATDstPort
	}

	var onMatchLabel string
	if negate {
		// Match negated, if we match any port then we jump to the next rule.
		onMatchLabel = p.endOfRuleLabel()
	} else {
		// Match is non-negated, if we match, go to the next match criteria.
		onMatchLabel = p.freshPerRuleLabel()
	}

	// R1 = port to test against.
	p.b.Load16(R1, R9, portOffset)

	for _, portRange := range ports {
		if portRange.First == portRange.Last {
			// Optimisation, single port, just do a comparison.
			p.b.JumpEqImm64(R1, portRange.First, onMatchLabel)
		} else {
			// Port range,
			var skipToNextPortLabel string
			if portRange.First > 0 {
				// If port is too low, skip to next port.
				skipToNextPortLabel = p.freshPerRuleLabel()
				p.b.JumpLTImm64(R1, portRange.First, skipToNextPortLabel)
			}
			// If port is in range, got a match, otherwise fall through to next port.
			p.b.JumpLEImm64(R1, portRange.Last, onMatchLabel)
			if portRange.First > 0 {
				p.b.LabelNextInsn(skipToNextPortLabel)
			}
		}
	}

	for _, ipSetID := range namedPorts {
		id := p.ipSetIDProvider.GetNoAlloc(ipSetID)
		if id == 0 {
			log.WithField("setID", ipSetID).Panic("Failed to look up IP set ID.")
		}

		var keyOffset int16
		if leg == legSource {
			p.setUpSrcIPSetKey(id)
			keyOffset = offSrcIPSetKey
		} else {
			p.setUpDstIPSetKey(id)
			keyOffset = offDstIPSetKey
		}

		p.b.LoadMapFD(R1, uint32(p.ipSetMapFD))
		p.b.Mov64(R2, R10)
		p.b.AddImm64(R2, int32(keyOffset))
		p.b.Call(HelperMapLookupElem)

		p.b.JumpNEImm64(R0, 0, onMatchLabel)
	}

	if !negate {
		// If we fall through then none of the ports matched so the rule doesn't match.
		p.b.Jump(p.endOfRuleLabel())
		// Label the next match so we can skip to it on success.
		p.b.LabelNextInsn(onMatchLabel)
	}
}

func (p *Builder) freshPerRuleLabel() string {
	part := p.rulePartID
	p.rulePartID++
	return fmt.Sprintf("rule_%d_part_%d", p.ruleID, part)
}

func (p *Builder) endOfRuleLabel() string {
	return fmt.Sprintf("rule_%d_no_match", p.ruleID)
}

func protocolToNumber(protocol *proto.Protocol) uint8 {
	var pcol uint8
	switch p := protocol.NumberOrName.(type) {
	case *proto.Protocol_Name:
		switch strings.ToLower(p.Name) {
		case "tcp":
			pcol = 6
		case "udp":
			pcol = 17
		case "icmp":
			pcol = 1
		case "sctp":
			pcol = 132
		}
	case *proto.Protocol_Number:
		pcol = uint8(p.Number)
	}
	return pcol
}
