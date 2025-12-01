// Copyright (c) 2020-2025 Tigera, Inc. All rights reserved.

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

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf/asm"
	"github.com/projectcalico/calico/felix/bpf/ipsets"
	"github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/bpf/state"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
)

// Verifier imposes a limit on how many jumps can be on the same code path.
const (
	verifierMaxJumpsLimit      = 8192
	maxJumpsHeadroom           = 200
	defaultPerProgramJumpLimit = verifierMaxJumpsLimit - maxJumpsHeadroom
)

type Builder struct {
	blocks          []*asm.Block
	b               *asm.Block
	tierID          int
	policyID        int
	ruleID          int
	rulePartID      int
	ipSetIDProvider ipSetIDProvider

	ipSetMapFD         maps.FD
	stateMapFD         maps.FD
	staticJumpMapFD    maps.FD
	policyJumpMapFD    maps.FD
	policyMapIndex     int
	policyMapStride    int
	policyDebugEnabled bool
	forIPv6            bool
	allowJmp           int
	denyJmp            int
	useJmps            bool
	maxJumpsPerProgram int
	numRulesInProgram  int
	xdp                bool
	flowLogsEnabled    bool
	trampolineStride   int
}

type ipSetIDProvider interface {
	GetNoAlloc(ipSetID string) uint64
}

// Option is an additional option that can change default behaviour
type Option func(b *Builder)

func NewBuilder(
	ipSetIDProvider ipSetIDProvider,
	ipsetMapFD, stateMapFD, staticProgsMapFD, policyJumpMapFD maps.FD,
	opts ...Option,
) *Builder {
	b := &Builder{
		ipSetIDProvider:    ipSetIDProvider,
		ipSetMapFD:         ipsetMapFD,
		stateMapFD:         stateMapFD,
		staticJumpMapFD:    staticProgsMapFD,
		policyJumpMapFD:    policyJumpMapFD,
		maxJumpsPerProgram: defaultPerProgramJumpLimit,
	}

	for _, option := range opts {
		option(b)
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

const (
	stateEventHdrSize int16 = 8
)

var (
	// Stack offsets.  These are defined locally.
	offStateKey = nextOffset(4, 4)
	// Even for v4 programs, we have the v6 layout
	// N.B. we can use 64bit stack stores in ipv6 because of the 4 byte alignment
	// preceded by the 4 bytes of StateKey. That makes the ip within the src key
	// 8 bytes aligned. And since the ip is followed by 4 bytes of
	// port+proto+pad, the dst key is also aligned in the same way. <sweat :-)>
	offSrcIPSetKey = nextOffset(ipsets.IPSetEntryV6Size, 4)
	offDstIPSetKey = nextOffset(ipsets.IPSetEntryV6Size, 4)

	// Offsets within the cal_tc_state struct.
	// WARNING: must be kept in sync with the definitions in bpf-gpl/types.h.
	stateOffIPSrc          = asm.FieldOffset{Offset: stateEventHdrSize + 0, Field: "state->ip_src"}
	stateOffIPDst          = asm.FieldOffset{Offset: stateEventHdrSize + 16, Field: "state->ip_dst"}
	_                      = stateOffIPDst
	stateOffPreNATIPDst    = asm.FieldOffset{Offset: stateEventHdrSize + 32, Field: "state->pre_nat_ip_dst"}
	_                      = stateOffPreNATIPDst
	stateOffPostNATIPDst   = asm.FieldOffset{Offset: stateEventHdrSize + 48, Field: "state->post_nat_ip_dst"}
	stateOffPolResult      = asm.FieldOffset{Offset: stateEventHdrSize + 84, Field: "state->pol_rc"}
	stateOffSrcPort        = asm.FieldOffset{Offset: stateEventHdrSize + 88, Field: "state->sport"}
	stateOffDstPort        = asm.FieldOffset{Offset: stateEventHdrSize + 90, Field: "state->dport"}
	_                      = stateOffDstPort
	stateOffICMPType       = asm.FieldOffset{Offset: stateEventHdrSize + 90, Field: "state->icmp_type"}
	stateOffPreNATDstPort  = asm.FieldOffset{Offset: stateEventHdrSize + 92, Field: "state->pre_nat_dport"}
	_                      = stateOffPreNATDstPort
	stateOffPostNATDstPort = asm.FieldOffset{Offset: stateEventHdrSize + 94, Field: "state->post_nat_dport"}
	stateOffIPProto        = asm.FieldOffset{Offset: stateEventHdrSize + 96, Field: "state->ip_proto"}
	stateOffIPSize         = asm.FieldOffset{Offset: stateEventHdrSize + 98, Field: "state->ip_size"}
	_                      = stateOffIPSize

	stateOffRulesHit = asm.FieldOffset{Offset: stateEventHdrSize + 100, Field: "state->rules_hit"}
	stateOffRuleIDs  = asm.FieldOffset{Offset: stateEventHdrSize + 104, Field: "state->rule_ids"}

	stateOffFlags = asm.FieldOffset{Offset: stateEventHdrSize + 360, Field: "state->flags"}

	skbCb0 = asm.FieldOffset{Offset: 12*4 + 0*4, Field: "skb->cb[0]"}
	skbCb1 = asm.FieldOffset{Offset: 12*4 + 1*4, Field: "skb->cb[1]"}

	// Compile-time check that IPSetEntryV6Size hasn't changed; if it changes, the code will need to change.
	_ = [1]struct{}{{}}[32-ipsets.IPSetEntryV6Size]

	// Offsets within struct ip4_set_key.
	// WARNING: must be kept in sync with the definitions in bpf/ipsets/map.go.
	// WARNING: must be kept in sync with the definitions in bpf/include/policy.h.
	ipsKeyPrefix int16 = 0
	ipsKeyID     int16 = 4
	ipsKeyAddr   int16 = 12
	ipsKeyPort   int16 = 16
	ipsKeyProto  int16 = 18
	ipsKeyPad    int16 = 19

	// Bits in the state flags field.
	FlagDestIsHost uint64 = 1 << 2
	FlagSrcIsHost  uint64 = 1 << 3
	FlagLogPacket  uint64 = 1 << 10
)

type Rule struct {
	*proto.Rule
	MatchID RuleMatchID
}

type Policy struct {
	Kind      string
	Namespace string
	Name      string
	Rules     []Rule
}

type Tier struct {
	Name      string
	EndRuleID RuleMatchID
	EndAction TierEndAction
	Policies  []Policy
}

type Rules struct {
	// Both workload and host interfaces can enforce host endpoint policy (carried here in the
	// Host... fields); in the case of a workload interface, that can only come from the
	// wildcard host endpoint, aka "host-*".
	//
	// However, only a workload interface can have any workload policy (carried here in the
	// Tiers and Profiles fields), and workload interfaces also Deny by default when there is no
	// workload policy at all.  ForHostInterface (with reversed polarity) is the boolean that
	// tells us whether or not to implement workload policy and that default Deny.
	ForHostInterface bool

	// Indicates to suppress normal host policy because it's trumped by the setting of
	// DefaultEndpointToHostAction.
	SuppressNormalHostPolicy bool

	// Workload policy.
	Tiers            []Tier
	Profiles         []Profile
	NoProfileMatchID RuleMatchID

	// Host endpoint policy.
	HostPreDnatTiers []Tier
	HostForwardTiers []Tier
	HostNormalTiers  []Tier
	HostProfiles     []Profile

	// True when building a policy program for XDP, as opposed to for TC.  This also means that
	// we are implementing untracked policy (provided in the HostNormalTiers field) and that
	// traffic is allowed to continue if not explicitly allowed or denied.
	ForXDP bool
}

type RuleMatchID = uint64

type Profile = Policy

type TierEndAction string

const (
	TierEndUndef TierEndAction = ""
	TierEndDeny  TierEndAction = "deny"
	TierEndPass  TierEndAction = "pass"
)

func (p *Builder) Instructions(rules Rules) ([]asm.Insns, error) {
	p.xdp = rules.ForXDP
	p.b = asm.NewBlock(p.policyDebugEnabled)
	p.b.SetTrampolineStride(p.trampolineStride)
	p.blocks = append(p.blocks, p.b)
	p.writeProgramHeader()

	if p.xdp {
		// For an XDP program HostNormalTiers continues the untracked policy to enforce;
		// other fields are unused.
		goto normalPolicy
	}

	// Pre-DNAT policy: on a host interface, or host-* policy on a workload interface.  Traffic
	// is allowed to continue if there is no applicable pre-DNAT policy.
	p.writeTiers(rules.HostPreDnatTiers, legDestPreNAT, "allowed_by_host_policy")

	// If traffic is to or from the local host, skip over any apply-on-forward policy.  Note
	// that this case can be:
	// - on a workload interface, workload <--> own host
	// - on a host interface, this host (not a workload) <--> anywhere outside this host
	//
	// When rules.SuppressNormalHostPolicy is true, we also skip normal host policy; this is
	// the case when we're building the policy program for workload -> host and
	// DefaultEndpointToHostAction is ACCEPT or DROP; or for host -> workload.
	if rules.SuppressNormalHostPolicy {
		p.writeJumpIfToOrFromHost("allowed_by_host_policy")
	} else {
		p.writeJumpIfToOrFromHost("to_or_from_host")
	}

	// At this point we know we have traffic that is being forwarded through the host's root
	// network namespace.  Note that this case can be:
	// - workload interface, workload <--> another local workload
	// - workload interface, workload <--> anywhere outside this host
	// - host interface, workload <--> anywhere outside this host
	// - host interface, anywhere outside this host <--> anywhere outside this host

	// Apply-On-Forward policy: on a host interface, or host-* policy on a workload interface.
	// Traffic is allowed to continue if there is no applicable AoF policy.
	p.writeTiers(rules.HostForwardTiers, legDest, "allowed_by_host_policy")

	// Now skip over normal host policy and jump to where we apply possible workload policy.
	p.b.Jump("allowed_by_host_policy")

normalPolicy:
	if !rules.SuppressNormalHostPolicy {
		// "Normal" host policy, i.e. for non-forwarded traffic.
		p.b.LabelNextInsn("to_or_from_host")
		if rules.ForXDP {
			p.writeTiers(rules.HostNormalTiers, legDestPreNAT, "allowed_by_host_policy")
			p.b.Jump("xdp_pass")
		} else {
			p.writeTiers(rules.HostNormalTiers, legDest, "allowed_by_host_policy")
			p.writeProfiles(rules.HostProfiles, rules.NoProfileMatchID, "allowed_by_host_policy")
		}
	}

	// End of host policy.
	p.b.LabelNextInsn("allowed_by_host_policy")

	if rules.ForHostInterface {
		// On a host interface there is no workload policy, so we are now done.
		p.b.Jump("allow")
	} else {
		// Workload policy.
		p.writeTiers(rules.Tiers, legDest, "allow")
		p.writeProfiles(rules.Profiles, rules.NoProfileMatchID, "allow")
	}

	p.writeProgramFooter()

	var progs []asm.Insns
	for i, b := range p.blocks {
		insns, err := b.Assemble()
		if err != nil {
			return nil, fmt.Errorf("failed to assemble policy program %d: %w", i, err)
		}
		progs = append(progs, insns)
	}
	return progs, nil
}

// writeProgramHeader emits instructions to load the state from the state map, leaving
// R6 = program context
// R9 = pointer to state map
func (p *Builder) writeProgramHeader() {
	// Preamble to the policy program.
	p.b.LabelNextInsn("start")
	p.b.Mov64(asm.R6, asm.R1) // Save R1 (context) in R6.
	// Zero-out the map key
	p.b.MovImm64(asm.R1, 0) // R1 = 0
	p.b.StoreStack32(asm.R1, offStateKey)
	// Get pointer to map key in R2.
	p.b.Mov64(asm.R2, asm.R10) // R2 = R10
	p.b.AddImm64(asm.R2, int32(offStateKey))
	// Load map file descriptor into R1.
	// clang uses a 64-bit load so copy that for now.
	p.b.AddComment("Load packet metadata saved by previous program")
	p.b.LoadMapFD(asm.R1, uint32(p.stateMapFD)) // R1 = 0 (64-bit immediate)
	p.b.Call(asm.HelperMapLookupElem)           // Call helper
	// Check return value for NULL.
	p.b.JumpEqImm64(asm.R0, 0, "exit")
	// Save state pointer in R9.
	p.b.AddComment("Save state pointer in register R9")
	p.b.Mov64(asm.R9, asm.R0)
	p.b.LabelNextInsn("policy")
}

func (p *Builder) writeJumpIfToOrFromHost(label string) {
	// Load state flags.
	p.b.Load64(asm.R1, asm.R9, stateOffFlags)

	// Mask against host bits.
	p.b.AndImm64(asm.R1, int32(FlagDestIsHost|FlagSrcIsHost))

	// If non-zero, jump to specified label.
	p.b.JumpNEImm64(asm.R1, 0, label)
}

// writeProgramFooter emits the program exit jump targets.
func (p *Builder) writeProgramFooter() {
	// Fall through here if there's no match.  Also used when we hit an error or if policy rejects packet.
	p.b.LabelNextInsn("deny")

	// Store the policy result in the state for the next program to see.
	p.b.MovImm32(asm.R1, int32(state.PolicyDeny))
	p.b.Store32(asm.R9, asm.R1, stateOffPolResult)

	// Execute the tail call to drop program
	p.b.Mov64(asm.R1, asm.R6)                        // First arg is the context.
	p.b.LoadMapFD(asm.R2, uint32(p.staticJumpMapFD)) // Second arg is the map.
	if p.useJmps {
		p.b.AddCommentF("Deny jump to %d", p.denyJmp)
		p.b.MovImm32(asm.R3, int32(p.denyJmp)) // Third arg is the index (rather than a pointer to the index).
	} else {
		p.b.Load32(asm.R3, asm.R6, skbCb1) // Third arg is the index from skb->cb[1]).
	}
	p.b.Call(asm.HelperTailCall)

	// Fall through if tail call fails.
	p.writeExitTarget()

	if p.xdp {
		p.b.LabelNextInsn("xdp_pass")
		p.b.MovImm64(asm.R0, 2 /* XDP_PASS */)
		p.b.Exit()
	}

	if p.b.TargetIsUsed("allow") {
		p.b.LabelNextInsn("allow")
		// Store the policy result in the state for the next program to see.
		p.b.MovImm32(asm.R1, int32(state.PolicyAllow))
		p.b.Store32(asm.R9, asm.R1, stateOffPolResult)
		// Execute the tail call.
		p.b.Mov64(asm.R1, asm.R6)                        // First arg is the context.
		p.b.LoadMapFD(asm.R2, uint32(p.staticJumpMapFD)) // Second arg is the map.
		if p.useJmps {
			p.b.AddCommentF("Allow jump to %d", p.allowJmp)
			p.b.MovImm32(asm.R3, int32(p.allowJmp)) // Third arg is the index (rather than a pointer to the index).
		} else {
			p.b.Load32(asm.R3, asm.R6, skbCb0) // Third arg is the index from skb->cb[0]).
		}
		p.b.Call(asm.HelperTailCall)

		// Fall through if tail call fails.
		p.b.MovImm32(asm.R1, state.PolicyTailCallFailed)
		p.b.Store32(asm.R9, asm.R1, stateOffPolResult)
		if p.xdp {
			p.b.MovImm64(asm.R0, 1 /* XDP_DROP */)
		} else {
			p.b.MovImm64(asm.R0, 2 /* TC_ACT_SHOT */)
		}
		p.b.Exit()
	}
}

func (p *Builder) writeExitTarget() {
	p.b.LabelNextInsn("exit")
	if p.xdp {
		p.b.MovImm64(asm.R0, 1 /* XDP_DROP */)
	} else {
		p.b.MovImm64(asm.R0, 2 /* TC_ACT_SHOT */)
	}
	p.b.Exit()
}

func (p *Builder) writeRecordRuleID(id RuleMatchID, skipLabel string) {
	// Load the hit count
	p.b.Load8(asm.R1, asm.R9, stateOffRulesHit)

	// Make sure we do not hit too many rules, if so skip to action without
	// recording the rule ID
	p.b.JumpGEImm64(asm.R1, state.MaxRuleIDs, skipLabel)

	// Increment the hit count
	p.b.Mov64(asm.R2, asm.R1)
	p.b.AddImm64(asm.R2, 1)
	// Store the new count
	p.b.Store8(asm.R9, asm.R2, stateOffRulesHit)

	// Store the rule ID in the rule ids array
	p.b.ShiftLImm64(asm.R1, 3) // x8
	p.b.AddImm64(asm.R1, int32(stateOffRuleIDs.Offset))
	p.b.LoadImm64(asm.R2, int64(id))
	p.b.Add64(asm.R1, asm.R9)
	p.b.Store64(asm.R1, asm.R2, asm.FieldOffset{Offset: 0, Field: ""})
}

func (p *Builder) writeRecordRuleHit(r Rule, skipLabel string) {
	log.Debugf("Hit rule ID 0x%x", r.MatchID)
	p.writeRecordRuleID(r.MatchID, skipLabel)
}

func (p *Builder) setUpIPSetKey(ipsetID uint64, keyOffset int16, ipOffset, portOffset asm.FieldOffset) {
	v6Adjust := int16(0)
	prefixLen := int32(128)

	if p.forIPv6 {
		// IPv6 addresses are 12 bytes longer and so everything beyond the
		// address is shifted by 12 bytes.
		v6Adjust = 12
		prefixLen += 96
	}

	// TODO track whether we've already done an initialisation and skip the parts that don't change.
	// Zero the padding.
	p.b.MovImm64(asm.R1, 0) // R1 = 0
	p.b.StoreStack8(asm.R1, keyOffset+ipsKeyPad+v6Adjust)
	p.b.MovImm64(asm.R1, prefixLen) // R1 = 128
	p.b.StoreStack32(asm.R1, keyOffset+ipsKeyPrefix)

	// Store the IP address, port and protocol.
	if !p.forIPv6 {
		p.b.Load32(asm.R1, asm.R9, ipOffset)
		p.b.StoreStack32(asm.R1, keyOffset+ipsKeyAddr)
	} else {
		p.b.Load64(asm.R1, asm.R9, ipOffset)
		p.b.StoreStack64(asm.R1, keyOffset+ipsKeyAddr)
		ipOffset.Offset += 8
		p.b.Load64(asm.R1, asm.R9, ipOffset)
		p.b.StoreStack64(asm.R1, keyOffset+ipsKeyAddr+8)
	}
	p.b.Load16(asm.R1, asm.R9, portOffset)
	p.b.StoreStack16(asm.R1, keyOffset+ipsKeyPort+v6Adjust)
	p.b.Load8(asm.R1, asm.R9, stateOffIPProto)
	p.b.StoreStack8(asm.R1, keyOffset+ipsKeyProto+v6Adjust)

	// Store the IP set ID.  It is 64-bit but, since it's a packed struct, we have to write it in two
	// 32-bit chunks.
	beIPSetID := bits.ReverseBytes64(ipsetID)
	p.b.MovImm32(asm.R1, int32(beIPSetID))
	p.b.StoreStack32(asm.R1, keyOffset+ipsKeyID)
	p.b.MovImm32(asm.R1, int32(beIPSetID>>32))
	p.b.StoreStack32(asm.R1, keyOffset+ipsKeyID+4)
}

func (p *Builder) writeTiers(tiers []Tier, destLeg matchLeg, allowLabel string) {
	actionLabels := map[string]string{
		"allow": allowLabel,
		"deny":  "deny",
		"log":   "log",
	}
	for _, tier := range tiers {
		endOfTierLabel := fmt.Sprint("end_of_tier_", p.tierID)
		actionLabels["pass"] = endOfTierLabel
		actionLabels["next-tier"] = endOfTierLabel

		log.Debugf("Start of tier %d %q", p.tierID, tier.Name)
		p.b.AddCommentF("Start of tier %s", tier.Name)
		for _, pol := range tier.Policies {
			p.writePolicy(pol, actionLabels, destLeg)
		}

		// End of tier rule.
		action := tier.EndAction
		if action == TierEndUndef {
			action = TierEndDeny
		}
		p.b.AddCommentF("End of tier %s: %s", tier.Name, tier.EndAction)
		log.Debugf("End of tier %d %q: %s", p.tierID, tier.Name, action)
		p.writeRule(Rule{
			Rule:    &proto.Rule{},
			MatchID: tier.EndRuleID,
		}, actionLabels[string(action)], destLeg)
		p.b.LabelNextInsn(endOfTierLabel)
		p.tierID++
	}
}

func (p *Builder) writeProfiles(profiles []Policy, noProfileMatchID uint64, allowLabel string) {
	log.Debugf("Start of profiles")
	for idx, prof := range profiles {
		p.writeProfile(prof, idx, allowLabel)
	}

	log.Debugf("End of profiles drop")
	p.writeRule(Rule{
		Rule:    &proto.Rule{},
		MatchID: noProfileMatchID,
	}, "deny", legDest)
}

func (p *Builder) writePolicyRules(policy Policy, actionLabels map[string]string, destLeg matchLeg) {
	for ruleIdx, rule := range policy.Rules {
		log.Debugf("Start of rule %d", ruleIdx)
		p.b.AddCommentF("Start of rule %s", rule)
		ipsets := p.printIPSetIDs(rule)
		if ipsets != "" {
			p.b.AddCommentF("IPSets %s", p.printIPSetIDs(rule))
		}
		p.b.AddCommentF("Rule MatchID: %d", rule.MatchID)
		action := strings.ToLower(rule.Action)
		p.writeRule(rule, actionLabels[action], destLeg)
		log.Debugf("End of rule %d", ruleIdx)
		p.b.AddCommentF("End of rule %s", rule.RuleId)
	}
}

func (p *Builder) writePolicy(policy Policy, actionLabels map[string]string, destLeg matchLeg) {
	// Identifying comment at the start and end of the policy.
	cmtID := fmt.Sprintf("%s %s %d", policy.Kind, policy.Name, p.policyID)
	if policy.Namespace != "" {
		cmtID = fmt.Sprintf("%s %s/%s %d", policy.Kind, policy.Namespace, policy.Name, p.policyID)
	}
	p.b.AddCommentF("Start of %s", cmtID)
	log.Debugf("Start of %s", cmtID)

	p.writePolicyRules(policy, actionLabels, destLeg)

	log.Debugf("End of %s", cmtID)
	p.b.AddCommentF("End of %s", cmtID)
	p.policyID++
}

func (p *Builder) writeProfile(profile Profile, idx int, allowLabel string) {
	actionLabels := map[string]string{
		"allow":     allowLabel,
		"deny":      "deny",
		"pass":      "deny",
		"next-tier": "deny",
	}
	log.Debugf("Start of profile %q %d", profile.Name, idx)
	p.writePolicyRules(profile, actionLabels, legDest)
	log.Debugf("End of profile %q %d", profile.Name, idx)
	p.policyID++
}

type matchLeg string

const (
	legSource     matchLeg = "source"
	legDest       matchLeg = "dest"
	legDestPreNAT matchLeg = "destPreNAT"
)

func (leg matchLeg) offsetToStateIPAddressField() (offset asm.FieldOffset) {
	switch leg {
	case legSource:
		offset = stateOffIPSrc
	case legDestPreNAT:
		offset = stateOffPreNATIPDst
	default:
		offset = stateOffPostNATIPDst
	}
	return
}

func (leg matchLeg) offsetToStatePortField() (portOffset asm.FieldOffset) {
	switch leg {
	case legSource:
		portOffset = stateOffSrcPort
	case legDestPreNAT:
		portOffset = stateOffPreNATDstPort
	default:
		portOffset = stateOffPostNATDstPort
	}
	return
}

func (leg matchLeg) stackOffsetToIPSetKey() (keyOffset int16) {
	if leg == legSource {
		keyOffset = offSrcIPSetKey
	} else {
		keyOffset = offDstIPSetKey
	}
	return
}

func (p *Builder) ipVersion() uint8 {
	if p.forIPv6 {
		return uint8(proto.IPVersion_IPV6)
	} else {
		return uint8(proto.IPVersion_IPV4)
	}
}

func (p *Builder) writeRule(r Rule, actionLabel string, destLeg matchLeg) {
	p.maybeSplitProgram()

	if actionLabel == "" {
		log.Panic("empty action label")
	}

	rule := rules.FilterRuleToIPVersion(p.ipVersion(), r.Rule)
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
		p.writeCIDRSMatch(false, destLeg, rule.DstNet)
	}
	if len(rule.NotDstNet) != 0 {
		log.WithField("cidrs", rule.NotDstNet).Debugf("NotDstNet match")
		p.writeCIDRSMatch(true, destLeg, rule.NotDstNet)
	}

	if len(rule.SrcIpSetIds) > 0 {
		log.WithField("ipSetIDs", rule.SrcIpSetIds).Debugf("SrcIpSetIds match")
		p.writeIPSetMatch(false, legSource, rule.SrcIpSetIds)
	}
	if len(rule.NotSrcIpSetIds) > 0 {
		log.WithField("ipSetIDs", rule.NotSrcIpSetIds).Debugf("NotSrcIpSetIds match")
		p.writeIPSetMatch(true, legSource, rule.NotSrcIpSetIds)
	}

	if len(rule.DstIpSetIds) > 1 {
		// We should only ever have one set here because they get combined in the calc graph.  Enterprise
		// depends on that so we assert here too.
		log.WithField("rule", rule).Panic("proto.Rule has more than one DstIpSetIds")
	}
	if len(rule.DstIpSetIds) > 0 {
		// writeIPSetOrMatch used here because Enterprise has >1 IP set that need to be ORed together.
		log.WithField("ipSetIDs", rule.DstIpSetIds).Debugf("DstIpSetIds match")
		p.writeIPSetOrMatch(destLeg, rule.DstIpSetIds)
	}
	if len(rule.NotDstIpSetIds) > 0 {
		log.WithField("ipSetIDs", rule.NotDstIpSetIds).Debugf("NotDstIpSetIds match")
		p.writeIPSetMatch(true, destLeg, rule.NotDstIpSetIds)
	}

	if len(rule.DstIpPortSetIds) > 0 {
		log.WithField("ipPortSetIDs", rule.DstIpPortSetIds).Debugf("DstIpPortSetIds match")
		p.writeIPSetMatch(false, destLeg, rule.DstIpPortSetIds)
	}

	if len(rule.SrcPorts) > 0 || len(rule.SrcNamedPortIpSetIds) > 0 {
		log.WithFields(log.Fields{
			"ports":   rule.SrcPorts,
			"set ids": rule.SrcNamedPortIpSetIds,
		}).Debugf("SrcPorts match")
		p.writePortsMatch(false, legSource, rule.SrcPorts, rule.SrcNamedPortIpSetIds)
	}
	if len(rule.NotSrcPorts) > 0 || len(rule.NotSrcNamedPortIpSetIds) > 0 {
		log.WithFields(log.Fields{
			"ports":   rule.NotSrcPorts,
			"set ids": rule.NotSrcNamedPortIpSetIds,
		}).Debugf("NotSrcPorts match")
		p.writePortsMatch(true, legSource, rule.NotSrcPorts, rule.NotSrcNamedPortIpSetIds)
	}

	if len(rule.DstPorts) > 0 || len(rule.DstNamedPortIpSetIds) > 0 {
		log.WithFields(log.Fields{
			"ports":   rule.DstPorts,
			"set ids": rule.DstNamedPortIpSetIds,
		}).Debugf("DstPorts match")
		p.writePortsMatch(false, destLeg, rule.DstPorts, rule.DstNamedPortIpSetIds)
	}
	if len(rule.NotDstPorts) > 0 || len(rule.NotDstNamedPortIpSetIds) > 0 {
		log.WithFields(log.Fields{
			"ports":   rule.NotDstPorts,
			"set ids": rule.NotDstNamedPortIpSetIds,
		}).Debugf("NotDstPorts match")
		p.writePortsMatch(true, destLeg, rule.NotDstPorts, rule.NotDstNamedPortIpSetIds)
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

	p.writeEndOfRule(r, actionLabel)
	p.ruleID++
	p.rulePartID = 0
	p.numRulesInProgram++
}

func (p *Builder) writeStartOfRule() {
}

func (p *Builder) writeEndOfRule(rule Rule, actionLabel string) {
	if actionLabel == "log" {
		p.b.Load64(asm.R1, asm.R9, stateOffFlags)
		p.b.OrImm64(asm.R1, int32(FlagLogPacket))
		p.b.Store64(asm.R9, asm.R1, stateOffFlags)
	} else {
		// If all the match criteria are met, we fall through to the end of the rule
		// so all that's left to do is to jump to the relevant action.
		// TODO log and log-and-xxx actions
		if p.flowLogsEnabled || p.policyDebugEnabled {
			p.writeRecordRuleHit(rule, actionLabel)
		}
		p.b.Jump(actionLabel)
	}

	p.b.LabelNextInsn(p.endOfRuleLabel())
}

func (p *Builder) writeProtoMatch(negate bool, protocol *proto.Protocol) {
	if negate {
		p.b.AddCommentF("If protocol == %s, skip to next rule", protocolToName(protocol))
	} else {
		p.b.AddCommentF("If protocol != %s, skip to next rule", protocolToName(protocol))
	}

	p.b.Load8(asm.R1, asm.R9, stateOffIPProto)
	protoNum := protocolToNumber(protocol)
	if negate {
		p.b.JumpEqImm64(asm.R1, int32(protoNum), p.endOfRuleLabel())
	} else {
		p.b.JumpNEImm64(asm.R1, int32(protoNum), p.endOfRuleLabel())
	}
}

func (p *Builder) writeICMPTypeMatch(negate bool, icmpType uint8) {
	if negate {
		p.b.AddCommentF("If ICMP type == %d, skip to next rule", icmpType)
	} else {
		p.b.AddCommentF("If ICMP type != %d, skip to next rule", icmpType)
	}
	p.b.Load8(asm.R1, asm.R9, stateOffICMPType)
	if negate {
		p.b.JumpEqImm64(asm.R1, int32(icmpType), p.endOfRuleLabel())
	} else {
		p.b.JumpNEImm64(asm.R1, int32(icmpType), p.endOfRuleLabel())
	}
}

func (p *Builder) writeICMPTypeCodeMatch(negate bool, icmpType, icmpCode uint8) {
	if negate {
		p.b.AddCommentF("If ICMP type == %d and code == %d, skip to next rule", icmpType, icmpCode)
	} else {
		p.b.AddCommentF("If ICMP type != %d or code != %d, skip to next rule", icmpType, icmpCode)
	}
	p.b.Load16(asm.R1, asm.R9, stateOffICMPType)
	if negate {
		p.b.JumpEqImm64(asm.R1, (int32(icmpCode)<<8)|int32(icmpType), p.endOfRuleLabel())
	} else {
		p.b.JumpNEImm64(asm.R1, (int32(icmpCode)<<8)|int32(icmpType), p.endOfRuleLabel())
	}
}

func (p *Builder) writeCIDRSMatch(negate bool, leg matchLeg, cidrs []string) {
	if p.policyDebugEnabled {
		cidrStrings := "{"
		if len(cidrs) == 0 {
			cidrStrings = "{}"
		}

		for _, cidrStr := range cidrs {
			cidrStrings = cidrStrings + fmt.Sprintf("%s,", cidrStr)
		}
		cidrStrings = cidrStrings[:len(cidrStrings)-1] + "}"

		if negate {
			p.b.AddCommentF("If %s in %s, skip to next rule", leg, cidrStrings)
		} else {
			p.b.AddCommentF("If %s not in %s, skip to next rule", leg, cidrStrings)
		}
	}

	var onMatchLabel string
	if negate {
		// Match negated, if we match any CIDR then we jump to the next rule.
		onMatchLabel = p.endOfRuleLabel()
	} else {
		// Match is non-negated, if we match, go to the next match criteria.
		onMatchLabel = p.freshPerRuleLabel()
	}

	size := ip.IPv4SizeDword
	if p.forIPv6 {
		size = ip.IPv6SizeDword
	}

	addrU32 := make([]uint32, size)
	maskU32 := make([]uint32, size)
	for cidrIndex, cidrStr := range cidrs {
		// Number of CIDRs isn't bounded so may need to split mid-rule.
		p.maybeSplitProgram()

		cidr := ip.MustParseCIDROrIP(cidrStr)
		if p.forIPv6 {
			addrU64P1, addrU64P2 := cidr.Addr().(ip.V6Addr).AsUint64Pair()
			addrU32[0] = bits.ReverseBytes32(uint32(addrU64P1 >> 32))
			addrU32[1] = bits.ReverseBytes32(uint32(addrU64P1))
			addrU32[2] = bits.ReverseBytes32(uint32(addrU64P2 >> 32))
			addrU32[3] = bits.ReverseBytes32(uint32(addrU64P2))

			var maskU64P1, maskU64P2 uint64
			if cidr.Prefix() > 64 {
				maskU64P1 = math.MaxUint64
				maskU64P2 = uint64(math.MaxUint64 << (128 - cidr.Prefix()) & math.MaxUint64)
			} else {
				maskU64P1 = uint64(math.MaxUint64 << (64 - cidr.Prefix()) & math.MaxUint64)
				maskU64P2 = 0
			}
			maskU32[0] = bits.ReverseBytes32(uint32(maskU64P1 >> 32))
			maskU32[1] = bits.ReverseBytes32(uint32(maskU64P1))
			maskU32[2] = bits.ReverseBytes32(uint32(maskU64P2 >> 32))
			maskU32[3] = bits.ReverseBytes32(uint32(maskU64P2))
		} else { // IPv4
			addrU32[0] = bits.ReverseBytes32(cidr.Addr().(ip.V4Addr).AsUint32())
			maskU32[0] = bits.ReverseBytes32(math.MaxUint32 << (32 - cidr.Prefix()) & math.MaxUint32)
		}

		lastAddr := addrU32[0]
		for section, addr := range addrU32 {
			// Optimisation: If mask for this section, i.e. this match, is 0,
			// then we can skip the match since the result of AND operation is
			// irrelevant of packet address. However, we need to check at least one 32bit section.
			if section > 0 && maskU32[section] == 0 {
				break
			}

			offset := leg.offsetToStateIPAddressField()
			offset.Offset += int16(section * 4)
			p.b.Load32(asm.R1, asm.R9, offset)
			p.b.MovImm32(asm.R2, int32(maskU32[section]))
			p.b.And32(asm.R2, asm.R1)

			lastAddr = addr
			// If a 32bits section of an IPv6 does not match, we can skip the rest and jump to the
			// next CIDR, rather than checking all 4 32bits sections.
			if section != len(addrU32)-1 {
				p.b.JumpNEImm32(asm.R2, int32(addr), p.endOfcidrV6Match(cidrIndex))
			}
		}

		p.b.JumpEqImm32(asm.R2, int32(lastAddr), onMatchLabel)
		if p.forIPv6 {
			p.b.LabelNextInsn(p.endOfcidrV6Match(cidrIndex))
		}
	}

	if !negate {
		// If we fall through then none of the CIDRs matched so the rule doesn't match.
		p.b.Jump(p.endOfRuleLabel())
		// Label the next match so we can skip to it on success.
		p.b.LabelNextInsn(onMatchLabel)
	}
}

func (p *Builder) printIPSetIDs(r Rule) string {
	str := ""
	joinIDs := func(ipSets []string) string {
		idString := []string{}
		for _, ipSetID := range ipSets {
			id := p.ipSetIDProvider.GetNoAlloc(ipSetID)
			if id != 0 {
				idString = append(idString, fmt.Sprintf("0x%x", id))
			}
		}
		return strings.Join(idString[:], ",")
	}
	srcIDString := joinIDs(r.SrcIpSetIds)
	if srcIDString != "" {
		str = str + fmt.Sprintf("src_ip_set_ids:<%s> ", srcIDString)
	}
	notSrcIDString := joinIDs(r.NotSrcIpSetIds)
	if notSrcIDString != "" {
		str = str + fmt.Sprintf("not_src_ip_set_ids:<%s> ", notSrcIDString)
	}
	dstIDString := joinIDs(r.DstIpSetIds)
	if dstIDString != "" {
		str = str + fmt.Sprintf("dst_ip_set_ids:<%s> ", dstIDString)
	}
	notDstIDString := joinIDs(r.NotDstIpSetIds)
	if notDstIDString != "" {
		str = str + fmt.Sprintf("not_dst_ip_set_ids:<%s> ", notDstIDString)
	}
	return str
}

func (p *Builder) writeIPSetMatch(negate bool, leg matchLeg, ipSets []string) {
	// IP sets are different to CIDRs, if we have multiple IP sets then they all have to match
	// so we treat them as independent match criteria.
	for _, ipSetID := range ipSets {
		id := p.ipSetIDProvider.GetNoAlloc(ipSetID)
		if id == 0 {
			log.WithField("setID", ipSetID).Panic("Failed to look up IP set ID.")
		}

		if negate {
			p.b.AddCommentF("If %s matches ipset %s (0x%x), skip to next rule", leg, ipSetID, id)
		} else {
			p.b.AddCommentF("If %s doesn't match ipset %s (0x%x), skip to next rule", leg, ipSetID, id)
		}

		keyOffset := leg.stackOffsetToIPSetKey()
		p.setUpIPSetKey(id, keyOffset, leg.offsetToStateIPAddressField(), leg.offsetToStatePortField())
		p.b.LoadMapFD(asm.R1, uint32(p.ipSetMapFD))
		p.b.Mov64(asm.R2, asm.R10)
		p.b.AddImm64(asm.R2, int32(keyOffset))
		p.b.Call(asm.HelperMapLookupElem)

		if negate {
			// Negated; if we got a hit (non-0) then the rule doesn't match.
			// (Otherwise we fall through to the next match criteria.)
			p.b.JumpNEImm64(asm.R0, 0, p.endOfRuleLabel())
		} else {
			// Non-negated; if we got a miss (0) then the rule can't match.
			// (Otherwise we fall through to the next match criteria.)
			p.b.JumpEqImm64(asm.R0, 0, p.endOfRuleLabel())
		}
	}
}

// Match if packet matches ANY of the given IP sets.
func (p *Builder) writeIPSetOrMatch(leg matchLeg, ipSets []string) {
	onMatchLabel := p.freshPerRuleLabel()

	for _, ipSetID := range ipSets {
		id := p.ipSetIDProvider.GetNoAlloc(ipSetID)
		if id == 0 {
			log.WithField("setID", ipSetID).Panic("Failed to look up IP set ID.")
		}

		if len(ipSets) == 1 {
			p.b.AddCommentF("If %s doesn't match ipset %s (0x%x), skip to next rule", leg, ipSetID, id)
		} else {
			p.b.AddCommentF("If %s doesn't match ipset %s (0x%x), jump to next ipset", leg, ipSetID, id)
		}

		keyOffset := leg.stackOffsetToIPSetKey()
		p.setUpIPSetKey(id, keyOffset, leg.offsetToStateIPAddressField(), leg.offsetToStatePortField())
		p.b.LoadMapFD(asm.R1, uint32(p.ipSetMapFD))
		p.b.Mov64(asm.R2, asm.R10)
		p.b.AddImm64(asm.R2, int32(keyOffset))
		p.b.Call(asm.HelperMapLookupElem)

		// If we got a hit (non-0) then packet matches one of the IP sets.
		// (Otherwise we fall through to try the next IP set.)
		p.b.JumpNEImm64(asm.R0, 0, onMatchLabel)
	}

	// If packet reaches here, it hasn't matched any of the IP sets.
	if len(ipSets) > 1 {
		p.b.AddCommentF("If %s doesn't match any of the IP sets, skip to next rule", leg)
	}
	p.b.Jump(p.endOfRuleLabel())
	// Label the next match so we can skip to it on success.
	p.b.LabelNextInsn(onMatchLabel)
}

func (p *Builder) writePortsMatch(negate bool, leg matchLeg, ports []*proto.PortRange, namedPorts []string) {
	// For a ports match, numeric ports and named ports are ORed together.  Check any
	// numeric ports first and then any named ports.
	var onMatchLabel string
	if negate {
		// Match negated, if we match any port then we jump to the next rule.
		onMatchLabel = p.endOfRuleLabel()
	} else {
		// Match is non-negated, if we match, go to the next match criteria.
		onMatchLabel = p.freshPerRuleLabel()
	}

	if p.policyDebugEnabled {
		portRangeStr := "{"
		for idx, portRange := range ports {
			portRangeStr = portRangeStr + protoPortRangeToString(portRange)
			if idx != len(ports)-1 {
				portRangeStr = portRangeStr + ","
			}
		}
		portRangeStr = portRangeStr + "}"
		if negate {
			p.b.AddCommentF("If %s port is within any of %s, skip to next rule", leg, portRangeStr)
		} else {
			p.b.AddCommentF("If %s port is not within any of %s, skip to next rule", leg, portRangeStr)
		}
	}
	// R1 = port to test against.
	p.b.Load16(asm.R1, asm.R9, leg.offsetToStatePortField())
	for _, portRange := range ports {
		if portRange.First == portRange.Last {
			// Optimisation, single port, just do a comparison.
			p.b.JumpEqImm64(asm.R1, portRange.First, onMatchLabel)
		} else {
			// Port range,
			var skipToNextPortLabel string
			if portRange.First > 0 {
				// If port is too low, skip to next port.
				skipToNextPortLabel = p.freshPerRuleLabel()
				p.b.JumpLTImm64(asm.R1, portRange.First, skipToNextPortLabel)
			}
			// If port is in range, got a match, otherwise fall through to next port.
			p.b.JumpLEImm64(asm.R1, portRange.Last, onMatchLabel)
			if portRange.First > 0 {
				p.b.LabelNextInsn(skipToNextPortLabel)
			}
		}

		// Number of ports not bounded so may need to split mid-rule.
		if p.maybeSplitProgram() {
			// Program was split so the next instruction goes in the new program.
			// Need to reload our register(s).
			p.b.Load16(asm.R1, asm.R9, leg.offsetToStatePortField())
		}
	}

	if p.policyDebugEnabled {
		namedPortStr := "{"
		for idx, ipSetID := range namedPorts {
			namedPortStr = namedPortStr + ipSetID
			if idx != len(namedPorts)-1 {
				namedPortStr = namedPortStr + ","
			}
		}
		namedPortStr = namedPortStr + "}"
		if negate {
			p.b.AddCommentF("If %s port is within any of the named ports %s, skip to next rule", leg, namedPortStr)
		} else {
			p.b.AddCommentF("If %s port is not within any of the named ports %s, skip to next rule", leg, namedPortStr)
		}
	}

	for _, ipSetID := range namedPorts {
		p.maybeSplitProgram()

		id := p.ipSetIDProvider.GetNoAlloc(ipSetID)
		if id == 0 {
			log.WithField("setID", ipSetID).Panic("Failed to look up IP set ID.")
		}
		keyOffset := leg.stackOffsetToIPSetKey()
		p.setUpIPSetKey(id, keyOffset, leg.offsetToStateIPAddressField(), leg.offsetToStatePortField())
		p.b.LoadMapFD(asm.R1, uint32(p.ipSetMapFD))
		p.b.Mov64(asm.R2, asm.R10)
		p.b.AddImm64(asm.R2, int32(keyOffset))
		p.b.Call(asm.HelperMapLookupElem)

		p.b.JumpNEImm64(asm.R0, 0, onMatchLabel)
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

func (p *Builder) endOfcidrV6Match(cidrIndex int) string {
	return fmt.Sprintf("rule_%d_cidr_%d_end", p.ruleID, cidrIndex)
}

// maybeSplitProgram checks how large/complex the program has become and, if
// it reaches the threshold, starts a new policy program and adds it to
// p.blocks.
//
// Returns true if the program was split.  After a split only the registers
// initialised by writeProgramHeader are valid so, if the caller was using
// any other registers, they must be recalculated if maybeSplitProgram returns
// true.
func (p *Builder) maybeSplitProgram() bool {
	// Verifier imposes a limit on how many jumps can be on a path through
	// the bytecode (taken or not).  Since our code falls through to the next
	// rule by default, to first approximation, all our jumps are on the same
	// path.
	if p.b.NumJumps < p.maxJumpsPerProgram {
		return false
	}
	if p.policyMapStride == 0 {
		// Cannot split; parameters not set.  We'll just have to hope the
		// program fits.
		return false
	}

	p.b.SetTrampolinesEnabled(false) // We're about to write a special trampoline...
	p.b.AddCommentF("Splitting program after %d jumps", p.b.NumJumps)
	p.b.MovImm64(asm.R0, 0)
	p.b.Jump("next-program")

	// Program footer takes care of "allow" "deny" "exit" labels.
	p.writeProgramFooter()

	// Find any jump targets that need to jump to the next program.  This may
	// include a next-tier label or an internal rule label, if we're called
	// from within a rule-writing method.
	var targets []string
	for _, t := range p.b.UnresolvedJumpTargets() {
		if t == "next-program" {
			// Skip our label, we're about to resolve that below.
			continue
		}
		targets = append(targets, t)
	}

	// Write a landing pad for each dangling jump target.  Each landing pad
	// sets R0 to a unique value before jumping to the next-program label.
	log.WithFields(log.Fields{
		"danglingTargets": targets,
		"numRules":        p.numRulesInProgram,
		"numJumps":        p.b.NumJumps,
		"numProgs":        len(p.blocks),
	}).Debug("Splitting policy program")
	for i, t := range targets {
		p.b.LabelNextInsn(t)
		p.b.MovImm64(asm.R0, int32(i+1))
		if i != len(targets)-1 {
			p.b.Jump("next-program")
		}
	}
	p.b.LabelNextInsn("next-program")
	// Stash the trampoline offset in the policy result so the next program
	// can pick it up.
	p.b.Store32(asm.R9, asm.R0, stateOffPolResult)
	// Calculate the index of the next program.
	// With a "stride" of 1000, the first sub-program is at position n, then
	// the second goes at position 1000+n, then the next at 2000+n and so on.
	// The current block is in p.blocks already so this will calculate 1000+n
	// on the first time through.
	jumpIdx := SubProgramJumpIdx(p.policyMapIndex, len(p.blocks), p.policyMapStride)

	p.b.Mov64(asm.R1, asm.R6)                        // First arg is the context.
	p.b.LoadMapFD(asm.R2, uint32(p.policyJumpMapFD)) // Second arg is the map.
	p.b.AddCommentF(fmt.Sprintf("Tail call to policy program at index %d * %d + %d = %d", p.policyMapStride, len(p.blocks), p.policyMapIndex, jumpIdx))
	p.b.MovImm64(asm.R3, int32(jumpIdx)) // Third arg is index to jump to.
	p.b.Call(asm.HelperTailCall)
	p.writeExitTarget() // Drop if tail call fails.

	// Now start the new program...
	p.numRulesInProgram = 0
	p.b = asm.NewBlock(p.policyDebugEnabled)
	p.b.SetTrampolineStride(p.trampolineStride)
	p.blocks = append(p.blocks, p.b)
	// Header initialises the long-lived registers.
	p.b.AddCommentF(fmt.Sprintf("##### Start of program %d #####", len(p.blocks)-1))
	p.writeProgramHeader()
	// Then write our trampoline.
	p.b.Load32(asm.R0, asm.R9, stateOffPolResult)
	// Reset the policy result field to its default value.
	p.b.MovImm32(asm.R1, 0)
	p.b.Store32(asm.R9, asm.R1, stateOffPolResult)
	for i, t := range targets {
		p.b.JumpEqImm64(asm.R0, int32(i+1), t)
	}
	// If none of the trampoline jumps hit then we fall through.  This
	// continues whatever code was being written when we were called.

	return true
}

func (p *Builder) TrampolineStride() int {
	return p.trampolineStride
}

func SubProgramJumpIdx(polProgIdx, subProgIdx, stride int) int {
	return polProgIdx + subProgIdx*stride
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

// WithPolicyDebug enables policy debug.
func WithPolicyDebugEnabled() Option {
	return func(b *Builder) {
		b.policyDebugEnabled = true
	}
}

func WithAllowDenyJumps(allow, deny int) Option {
	return func(b *Builder) {
		b.allowJmp = allow
		b.denyJmp = deny
		b.useJmps = true
	}
}

// WithPolicyMapIndexAndStride tells the builder the "shape" of the policy
// jump map, allowing it to split the program if it gets too large.
// entryPointIdx is the jump map key for the first "entry point" program.
// stride is the number of indexes to skip to get to the next sub-program.
// If WithPolicyMapIndexAndStride is not provided, program-splitting is
// disabled.
func WithPolicyMapIndexAndStride(entryPointIdx, stride int) Option {
	return func(b *Builder) {
		b.policyMapIndex = entryPointIdx
		b.policyMapStride = stride
	}
}

func WithIPv6() Option {
	return func(p *Builder) {
		p.forIPv6 = true
	}
}

func WithFlowLogs() Option {
	return func(p *Builder) {
		p.flowLogsEnabled = true
	}
}

func WithTrampolineStride(s int) Option {
	return func(p *Builder) {
		p.trampolineStride = s
	}
}

func protocolToName(protocol *proto.Protocol) string {
	var pcol string
	switch p := protocol.NumberOrName.(type) {
	case *proto.Protocol_Name:
		return strings.ToLower(p.Name)
	case *proto.Protocol_Number:
		switch p.Number {
		case 6:
			pcol = "tcp"
		case 11:
			pcol = "udp"
		case 1:
			pcol = "icmp"
		case 132:
			pcol = "sctp"
		}
	}
	return pcol
}

func protoPortRangeToString(portRange *proto.PortRange) string {
	if portRange.First == portRange.Last {
		return fmt.Sprintf("%d", portRange.First)
	}
	return fmt.Sprintf("%d-%d", portRange.First, portRange.Last)
}
