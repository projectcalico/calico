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

package rules

import (
	"crypto/sha3"
	"encoding/base64"
	"fmt"
	"hash"
	"strconv"
	"strings"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/generictables"
	"github.com/projectcalico/calico/felix/iptables"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	calicohash "github.com/projectcalico/calico/libcalico-go/lib/hash"
)

const (
	ingressPolicy         = "ingress"
	egressPolicy          = "egress"
	alwaysAllowVXLANEncap = true
	alwaysAllowIPIPEncap  = true
)

type TierPolicyGroups struct {
	Name            string
	DefaultAction   string
	IngressPolicies []*PolicyGroup
	EgressPolicies  []*PolicyGroup
}

func (r *DefaultRuleRenderer) WorkloadEndpointToIptablesChains(
	ifaceName string,
	epMarkMapper EndpointMarkMapper,
	adminUp bool,
	tiers []TierPolicyGroups,
	profileIDs []string,
	qosControls *proto.QoSControls,
) []*generictables.Chain {
	allowVXLANEncapFromWorkloads := r.AllowVXLANPacketsFromWorkloads
	allowIPIPEncapFromWorkloads := r.AllowIPIPPacketsFromWorkloads
	result := []*generictables.Chain{}
	result = append(result,
		// Chain for traffic _to_ the endpoint.
		r.endpointIptablesChain(
			tiers,
			profileIDs,
			ifaceName,
			PolicyInboundPfx,
			ProfileInboundPfx,
			WorkloadToEndpointPfx,
			"", // No fail-safe chains for workloads.
			chainTypeNormal,
			adminUp,
			NFLOGInboundGroup,
			RuleDirIngress,
			ingressPolicy,
			r.filterAllowAction, // Workload endpoint chains are only used in the filter table
			alwaysAllowVXLANEncap,
			alwaysAllowIPIPEncap,
			qosControls,
		),
		// Chain for traffic _from_ the endpoint.
		// Encap traffic is blocked by default from workload endpoints
		// unless explicitly overridden.
		r.endpointIptablesChain(
			tiers,
			profileIDs,
			ifaceName,
			PolicyOutboundPfx,
			ProfileOutboundPfx,
			WorkloadFromEndpointPfx,
			"", // No fail-safe chains for workloads.
			chainTypeNormal,
			adminUp,
			NFLOGOutboundGroup,
			RuleDirEgress,
			egressPolicy,
			r.filterAllowAction, // Workload endpoint chains are only used in the filter table
			allowVXLANEncapFromWorkloads,
			allowIPIPEncapFromWorkloads,
			qosControls,
		),
	)

	if r.KubeIPVSSupportEnabled {
		// Chain for setting endpoint mark of an endpoint.
		result = append(result,
			r.endpointSetMarkChain(
				ifaceName,
				epMarkMapper,
				SetEndPointMarkPfx,
			),
		)
	}

	return result
}

func (r *DefaultRuleRenderer) HostEndpointToFilterChains(
	ifaceName string,
	tiers []TierPolicyGroups,
	forwardTiers []TierPolicyGroups,
	epMarkMapper EndpointMarkMapper,
	profileIDs []string,
) []*generictables.Chain {
	logrus.WithField("ifaceName", ifaceName).Debug("Rendering filter host endpoint chain.")
	result := []*generictables.Chain{}
	result = append(result,
		// Chain for output traffic _to_ the endpoint.
		r.endpointIptablesChain(
			tiers,
			profileIDs,
			ifaceName,
			PolicyOutboundPfx,
			ProfileOutboundPfx,
			HostToEndpointPfx,
			ChainFailsafeOut,
			chainTypeNormal,
			true, // Host endpoints are always admin up.
			NFLOGOutboundGroup,
			RuleDirEgress,
			egressPolicy,
			r.filterAllowAction,
			alwaysAllowVXLANEncap,
			alwaysAllowIPIPEncap,
			nil,
		),
		// Chain for input traffic _from_ the endpoint.
		r.endpointIptablesChain(
			tiers,
			profileIDs,
			ifaceName,
			PolicyInboundPfx,
			ProfileInboundPfx,
			HostFromEndpointPfx,
			ChainFailsafeIn,
			chainTypeNormal,
			true, // Host endpoints are always admin up.
			NFLOGInboundGroup,
			RuleDirIngress,
			ingressPolicy,
			r.filterAllowAction,
			alwaysAllowVXLANEncap,
			alwaysAllowIPIPEncap,
			nil,
		),
		// Chain for forward traffic _to_ the endpoint.
		r.endpointIptablesChain(
			forwardTiers,
			profileIDs,
			ifaceName,
			PolicyOutboundPfx,
			ProfileOutboundPfx,
			HostToEndpointForwardPfx,
			"", // No fail-safe chains for forward traffic.
			chainTypeForward,
			true, // Host endpoints are always admin up.
			NFLOGOutboundGroup,
			RuleDirEgress,
			egressPolicy,
			r.filterAllowAction,
			alwaysAllowVXLANEncap,
			alwaysAllowIPIPEncap,
			nil,
		),
		// Chain for forward traffic _from_ the endpoint.
		r.endpointIptablesChain(
			forwardTiers,
			profileIDs,
			ifaceName,
			PolicyInboundPfx,
			ProfileInboundPfx,
			HostFromEndpointForwardPfx,
			"", // No fail-safe chains for forward traffic.
			chainTypeForward,
			true, // Host endpoints are always admin up.
			NFLOGInboundGroup,
			RuleDirIngress,
			ingressPolicy,
			r.filterAllowAction,
			alwaysAllowVXLANEncap,
			alwaysAllowIPIPEncap,
			nil,
		),
	)

	if r.KubeIPVSSupportEnabled {
		// Chain for setting endpoint mark of an endpoint.
		result = append(result,
			r.endpointSetMarkChain(
				ifaceName,
				epMarkMapper,
				SetEndPointMarkPfx,
			),
		)
	}

	return result
}

func (r *DefaultRuleRenderer) HostEndpointToMangleEgressChains(
	ifaceName string,
	tiers []TierPolicyGroups,
	profileIDs []string,
) []*generictables.Chain {
	logrus.WithField("ifaceName", ifaceName).Debug("Render host endpoint mangle egress chain.")
	return []*generictables.Chain{
		// Chain for output traffic _to_ the endpoint.  Note, we use RETURN here rather than
		// ACCEPT because the mangle table is typically used, if at all, for packet
		// manipulations that might need to apply to our allowed traffic.
		r.endpointIptablesChain(
			tiers,
			profileIDs,
			ifaceName,
			PolicyOutboundPfx,
			ProfileOutboundPfx,
			HostToEndpointPfx,
			ChainFailsafeOut,
			chainTypeNormal,
			true, // Host endpoints are always admin up.
			NFLOGOutboundGroup,
			RuleDirEgress,
			egressPolicy,
			r.Return(),
			alwaysAllowVXLANEncap,
			alwaysAllowIPIPEncap,
			nil,
		),
	}
}

func (r *DefaultRuleRenderer) HostEndpointToRawEgressChain(
	ifaceName string,
	untrackedTiers []TierPolicyGroups,
) *generictables.Chain {
	logrus.WithField("ifaceName", ifaceName).Debug("Rendering raw (untracked) host endpoint egress chain.")
	return r.endpointIptablesChain(
		untrackedTiers,
		nil, // We don't render profiles into the raw table.
		ifaceName,
		PolicyOutboundPfx,
		ProfileOutboundPfx,
		HostToEndpointPfx,
		ChainFailsafeOut,
		chainTypeUntracked,
		true, // Host endpoints are always admin up.
		NFLOGOutboundGroup,
		RuleDirEgress,
		egressPolicy,
		r.Allow(),
		alwaysAllowVXLANEncap,
		alwaysAllowIPIPEncap,
		nil,
	)
}

func (r *DefaultRuleRenderer) HostEndpointToRawChains(
	ifaceName string,
	untrackedTiers []TierPolicyGroups,
) []*generictables.Chain {
	logrus.WithField("ifaceName", ifaceName).Debugf("Rendering raw (untracked) host endpoint chain. - untrackedTiers %+v", untrackedTiers)
	return []*generictables.Chain{
		// Chain for traffic _to_ the endpoint.
		r.HostEndpointToRawEgressChain(ifaceName, untrackedTiers),
		// Chain for traffic _from_ the endpoint.
		r.endpointIptablesChain(
			untrackedTiers,
			nil, // We don't render profiles into the raw table.
			ifaceName,
			PolicyInboundPfx,
			ProfileInboundPfx,
			HostFromEndpointPfx,
			ChainFailsafeIn,
			chainTypeUntracked,
			true, // Host endpoints are always admin up.
			NFLOGInboundGroup,
			RuleDirIngress,
			ingressPolicy,
			r.Allow(),
			alwaysAllowVXLANEncap,
			alwaysAllowIPIPEncap,
			nil,
		),
	}
}

func (r *DefaultRuleRenderer) HostEndpointToMangleIngressChains(
	ifaceName string,
	preDNATTiers []TierPolicyGroups,
) []*generictables.Chain {
	logrus.WithField("ifaceName", ifaceName).Debug("Rendering pre-DNAT host endpoint chain.")
	return []*generictables.Chain{
		// Chain for traffic _from_ the endpoint.  Pre-DNAT policy does not apply to
		// outgoing traffic through a host endpoint.
		r.endpointIptablesChain(
			preDNATTiers,
			nil, // We don't render profiles into the raw table.
			ifaceName,
			PolicyInboundPfx,
			ProfileInboundPfx,
			HostFromEndpointPfx,
			ChainFailsafeIn,
			chainTypePreDNAT,
			true, // Host endpoints are always admin up.
			NFLOGInboundGroup,
			RuleDirIngress,
			ingressPolicy,
			r.mangleAllowAction,
			alwaysAllowVXLANEncap,
			alwaysAllowIPIPEncap,
			nil,
		),
	}
}

type endpointChainType int

const (
	chainTypeNormal endpointChainType = iota
	chainTypeUntracked
	chainTypePreDNAT
	chainTypeForward
)

func (r *DefaultRuleRenderer) endpointSetMarkChain(
	name string,
	epMarkMapper EndpointMarkMapper,
	endpointPrefix string,
) *generictables.Chain {
	rules := []generictables.Rule{}
	chainName := EndpointChainName(endpointPrefix, name, r.maxNameLength)

	if endPointMark, err := epMarkMapper.GetEndpointMark(name); err == nil {
		// Set endpoint mark.
		rules = append(rules, generictables.Rule{Match: r.NewMatch(), Action: r.SetMaskedMark(endPointMark, epMarkMapper.GetMask())})
	}
	return &generictables.Chain{
		Name:  chainName,
		Rules: rules,
	}
}

func (r *DefaultRuleRenderer) PolicyGroupToIptablesChains(group *PolicyGroup) []*generictables.Chain {
	rules := make([]generictables.Rule, 0, len(group.Policies)*2-1)
	polChainPrefix := PolicyInboundPfx
	if group.Direction == PolicyDirectionOutbound {
		polChainPrefix = PolicyOutboundPfx
	}
	// To keep the number of rules low, we only drop a RETURN rule every
	// returnStride jump rules and only if one of the jump rules was to a
	// non-staged policy.  Staged policies don't set the mark bits when they
	// fire.
	const returnStride = 5
	count := -1
	for _, pol := range group.Policies {
		if model.KindIsStaged(pol.Kind) {
			logrus.Debugf("Skip programming staged policy %v", pol)
			continue
		}
		count++
		if count != 0 && count%returnStride == 0 {
			// If policy makes a verdict (i.e. the pass or accept bit is
			// non-zero) return to the per-endpoint chain.  Note: the per-endpoint
			// chain has a similar rule that only checks the accept bit.  Pass
			// is handled differently in the per-endpoint chain because we need
			// to continue processing in the same chain on a pass rule.
			rules = append(rules, generictables.Rule{
				Match:   r.NewMatch().MarkNotClear(r.MarkPass | r.MarkAccept),
				Action:  r.Return(),
				Comment: []string{"Return on verdict"},
			})
		}

		var match generictables.MatchCriteria
		if count%returnStride == 0 {
			// Optimisation, we're the first rule in a block, immediately after
			// start of chain or a RETURN rule, or, there are no non-staged
			// policies ahead of us (so the mark bits cannot be set).
			match = r.NewMatch()
		} else {
			// We're not the first rule in a block, only jump to this policy if
			// the previous policy didn't set a mark bit.
			match = r.NewMatch().MarkClear(r.MarkPass | r.MarkAccept)
		}

		chainToJumpTo := PolicyChainName(
			polChainPrefix,
			pol,
			r.nft,
		)
		rules = append(rules, generictables.Rule{
			Match:  match,
			Action: r.Jump(chainToJumpTo),
		})
	}
	return []*generictables.Chain{{
		Name:  group.ChainName(),
		Rules: rules,
	}}
}

// endpointIptablesChain sets up iptables rules for an endpoint chain.
func (r *DefaultRuleRenderer) endpointIptablesChain(
	tiers []TierPolicyGroups,
	profileIds []string,
	name string,
	policyPrefix PolicyChainNamePrefix,
	profilePrefix ProfileChainNamePrefix,
	endpointPrefix string,
	failsafeChain string,
	chainType endpointChainType,
	adminUp bool,
	nflogGroup uint16,
	dir RuleDir,
	policyType string,
	allowAction generictables.Action,
	allowVXLANEncap bool,
	allowIPIPEncap bool,
	qosControls *proto.QoSControls,
) *generictables.Chain {
	rules := []generictables.Rule{}

	chainName := EndpointChainName(endpointPrefix, name, r.maxNameLength)

	if !adminUp {
		// Endpoint is admin-down, drop all traffic to/from it.
		rules = append(rules, generictables.Rule{
			Match:   r.NewMatch(),
			Action:  r.IptablesFilterDenyAction(),
			Comment: []string{"Endpoint admin disabled"},
		})
		return &generictables.Chain{
			Name:  chainName,
			Rules: rules,
		}
	}

	// Add QoS controls for packet rate if applicable
	if chainType == chainTypeNormal && qosControls != nil {
		logrus.WithField("qosControls", qosControls).Debug("Rendering QoS controls packet rate rules")
		markLimitPacketRate := r.MarkScratch0
		if dir == RuleDirIngress {
			// Add ingress packet rate limit rules if applicable
			if qosControls.IngressPacketRate != 0 {
				logrus.WithFields(logrus.Fields{"IngressPacketRate": qosControls.IngressPacketRate, "IngressPacketBurst": qosControls.IngressPacketBurst, "mark": markLimitPacketRate}).Debug("Rendering ingress packet rate limit rules")
				if r.nft {
					rules = append(rules,
						generictables.Rule{
							Match:   r.NewMatch(),
							Action:  r.LimitPacketRate(qosControls.IngressPacketRate, qosControls.IngressPacketBurst, markLimitPacketRate),
							Comment: []string{"Drop packets over ingress packet rate limit"},
						},
					)
				} else {
					rules = append(rules,
						generictables.Rule{
							Match:   r.NewMatch(),
							Action:  r.ClearMark(markLimitPacketRate),
							Comment: []string{"Clear ingress packet rate limit mark"},
						},
						generictables.Rule{
							Match:   r.NewMatch(),
							Action:  r.LimitPacketRate(qosControls.IngressPacketRate, qosControls.IngressPacketBurst, markLimitPacketRate),
							Comment: []string{"Mark packets within ingress packet rate limit"},
						},
						generictables.Rule{
							Match:   r.NewMatch().NotMarkMatchesWithMask(markLimitPacketRate, markLimitPacketRate),
							Action:  r.Drop(),
							Comment: []string{"Drop packets over ingress packet rate limit"},
						},
						generictables.Rule{
							Match:   r.NewMatch(),
							Action:  r.ClearMark(markLimitPacketRate),
							Comment: []string{"Clear ingress packet rate limit mark"},
						},
					)
				}
			}
		}
		if dir == RuleDirEgress {
			// Add egress packet rate limit rules if applicable
			if qosControls.EgressPacketRate != 0 {
				logrus.WithFields(logrus.Fields{"EgressPacketRate": qosControls.EgressPacketRate, "EgressPacketBurst": qosControls.EgressPacketBurst, "mark": markLimitPacketRate}).Debug("Rendering egress packet rate limit rules")
				if r.nft {
					rules = append(rules,
						generictables.Rule{
							Match:   r.NewMatch(),
							Action:  r.LimitPacketRate(qosControls.EgressPacketRate, qosControls.EgressPacketBurst, markLimitPacketRate),
							Comment: []string{"Drop packets over egress packet rate limit"},
						},
					)
				} else {
					rules = append(rules,
						generictables.Rule{
							Match:   r.NewMatch(),
							Action:  r.ClearMark(markLimitPacketRate),
							Comment: []string{"Clear egress packet rate limit mark"},
						},
						generictables.Rule{
							Match:   r.NewMatch(),
							Action:  r.LimitPacketRate(qosControls.EgressPacketRate, qosControls.EgressPacketBurst, markLimitPacketRate),
							Comment: []string{"Mark packets within egress packet rate limit"},
						},
						generictables.Rule{
							Match:   r.NewMatch().NotMarkMatchesWithMask(markLimitPacketRate, markLimitPacketRate),
							Action:  r.Drop(),
							Comment: []string{"Drop packets over egress packet rate limit"},
						},
						generictables.Rule{
							Match:   r.NewMatch(),
							Action:  r.ClearMark(markLimitPacketRate),
							Comment: []string{"Clear egress packet rate limit mark"},
						},
					)
				}
			}
		}
	}

	if chainType != chainTypeUntracked {
		// Tracked chain: install conntrack rules, which implement our stateful connections.
		// This allows return traffic associated with a previously-permitted request.
		rules = r.appendConntrackRules(rules, allowAction)
	}

	// Add QoS controls for number of connections if applicable
	if chainType == chainTypeNormal && qosControls != nil {
		logrus.WithField("qosControls", qosControls).Debug("Rendering QoS controls number of connection rules")
		if dir == RuleDirIngress {
			// Add ingress connection limit rules if applicable
			if qosControls.IngressMaxConnections != 0 {
				logrus.WithFields(logrus.Fields{"IngressMaxConnections": qosControls.IngressMaxConnections}).Debug("Rendering ingress connection limit rules")
				rules = append(rules,
					generictables.Rule{
						Match:   r.NewMatch(),
						Action:  r.LimitNumConnections(qosControls.IngressMaxConnections, generictables.RejectWithTCPReset),
						Comment: []string{"Reject connections over ingress connection limit"},
					},
				)
			}
		}
		if dir == RuleDirEgress {
			// Add egress connection limit rules if applicable
			if qosControls.EgressMaxConnections != 0 {
				logrus.WithFields(logrus.Fields{"EgressMaxConnections": qosControls.EgressMaxConnections}).Debug("Rendering egress connection limit rules")
				rules = append(rules,
					generictables.Rule{
						Match:   r.NewMatch(),
						Action:  r.LimitNumConnections(qosControls.EgressMaxConnections, generictables.RejectWithTCPReset),
						Comment: []string{"Reject connections over egress connection limit"},
					},
				)
			}
		}
	}

	// First set up failsafes.
	if failsafeChain != "" {
		rules = append(rules, generictables.Rule{
			Match:  r.NewMatch(),
			Action: r.Jump(failsafeChain),
		})
	}

	// Start by ensuring that the policy result bits are clear.  Policy chains
	// set one of the bits to return their result (or leave the bits unset if
	// there's no match).
	rules = append(rules, generictables.Rule{
		Match:  r.NewMatch(),
		Action: r.ClearMark(r.MarkAccept | r.MarkPass),
	})

	if !allowVXLANEncap {
		// VXLAN encapped packets that originated in a pod should be dropped, as the encapsulation can be used to
		// bypass restrictive egress policies.
		rules = append(rules, generictables.Rule{
			Match: r.NewMatch().ProtocolNum(ProtoUDP).
				DestPorts(uint16(r.VXLANPort)),
			Action:  r.IptablesFilterDenyAction(),
			Comment: []string{fmt.Sprintf("%s VXLAN encapped packets originating in workloads", r.IptablesFilterDenyAction())},
		})
	}
	if !allowIPIPEncap {
		// IPinIP encapped packets that originated in a pod should be dropped, as the encapsulation can be used to
		// bypass restrictive egress policies.
		rules = append(rules, generictables.Rule{
			Match:   r.NewMatch().ProtocolNum(ProtoIPIP),
			Action:  r.IptablesFilterDenyAction(),
			Comment: []string{fmt.Sprintf("%s IPinIP encapped packets originating in workloads", r.IptablesFilterDenyAction())},
		})
	}

	for _, tier := range tiers {
		var policyGroups []*PolicyGroup
		if policyType == ingressPolicy {
			policyGroups = tier.IngressPolicies
		} else {
			policyGroups = tier.EgressPolicies
		}
		if len(policyGroups) > 0 {
			// Clear the "pass" mark.  If a policy sets that mark, we'll skip the rest of the policies and
			// continue processing the profiles, if there are any.
			rules = append(rules, generictables.Rule{
				Match:   r.NewMatch(),
				Action:  r.ClearMark(r.MarkPass),
				Comment: []string{"Start of tier " + tier.Name},
			})

			// Track if any of the policies are not staged. If all of the policies in a tier are staged
			// then the default end of tier behavior should be pass rather than drop.
			endOfTierDrop := false

			for _, polGroup := range policyGroups {
				var chainsToJumpTo []string
				groupHasNonStagedPols := polGroup.HasNonStagedPolicies()
				if groupHasNonStagedPols {
					endOfTierDrop = true
				}
				if polGroup.ShouldBeInlined() {
					// Group is too small to have its own chain.
					for _, p := range polGroup.Policies {
						if model.KindIsStaged(p.Kind) {
							logrus.Debugf("Skip programming inlined staged policy %v", p)
							continue
						}
						chainsToJumpTo = append(chainsToJumpTo, PolicyChainName(
							policyPrefix,
							p,
							r.nft,
						))
					}
				} else {
					// Group needs its own chain.
					chainsToJumpTo = []string{polGroup.ChainName()}
				}
				// Then, jump to each policy in turn.
				for _, chainToJumpTo := range chainsToJumpTo {
					// If a previous policy/group didn't set the "pass" mark, jump to the policy.
					rules = append(rules, generictables.Rule{
						Match:  r.NewMatch().MarkClear(r.MarkPass),
						Action: r.Jump(chainToJumpTo),
					})

					// Optimisation: skip rendering return rules if we know all the policies in
					// the group are staged.  Staged policies do not set the accept/pass mark bits
					// when they fire.
					if !groupHasNonStagedPols {
						continue
					}

					// If policy marked packet as accepted, it returns, setting the accept
					// mark bit.
					if chainType == chainTypeUntracked {
						// For an untracked policy, map allow to "NOTRACK and ALLOW".
						rules = append(rules, generictables.Rule{
							Match:  r.NewMatch().MarkSingleBitSet(r.MarkAccept),
							Action: r.NoTrack(),
						})
					}
					// If accept bit is set, return from this chain.  We don't immediately
					// accept because there may be other policy still to apply.
					rules = append(rules, generictables.Rule{
						Match:   r.NewMatch().MarkSingleBitSet(r.MarkAccept),
						Action:  r.Return(),
						Comment: []string{"Return if policy accepted"},
					})
				}
			}

			if chainType == chainTypeNormal || chainType == chainTypeForward {
				if endOfTierDrop && tier.DefaultAction != string(v3.Pass) {
					// When rendering normal and forward rules, if no policy marked the packet as "pass", drop the
					// packet.
					//
					// For untracked and pre-DNAT rules, we don't do that because there may be
					// normal rules still to be applied to the packet in the filter table.
					if r.FlowLogsEnabled {
						rules = append(rules, generictables.Rule{
							Match:  r.NewMatch().MarkClear(r.MarkPass),
							Action: r.Nflog(nflogGroup, CalculateEndOfTierDropNFLOGPrefixStr(dir, tier.Name), 0),
						})
					}
					rules = append(rules, generictables.Rule{
						Match:  r.NewMatch().MarkClear(r.MarkPass),
						Action: r.IptablesFilterDenyAction(),
						Comment: []string{
							fmt.Sprintf("End of tier %s. %s if no policies passed packet",
								tier.Name,
								r.IptablesFilterDenyAction()),
						},
					})
				} else if r.FlowLogsEnabled {
					// If we do not require an end of tier drop (i.e. because all of the policies in the tier are
					// staged), then add an end of tier pass nflog action so that we can at least track that we
					// would hit end of tier drop. This simplifies the processing in the collector.
					rules = append(rules, generictables.Rule{
						Match:  r.NewMatch().MarkClear(r.MarkPass),
						Action: r.Nflog(nflogGroup, CalculateEndOfTierPassNFLOGPrefixStr(dir, tier.Name), 0),
					})
				}
			}
		}
	}

	if len(tiers) == 0 && chainType == chainTypeForward {
		// Forwarded traffic is allowed when there are no policies with
		// applyOnForward that apply to this endpoint (and in this direction).
		rules = append(rules, generictables.Rule{
			Match:   r.NewMatch(),
			Action:  r.SetMark(r.MarkAccept),
			Comment: []string{"Allow forwarded traffic by default"},
		})
		rules = append(rules, generictables.Rule{
			Match:   r.NewMatch(),
			Action:  r.Return(),
			Comment: []string{"Return for accepted forward traffic"},
		})
	}

	if chainType == chainTypeNormal {
		// Then, jump to each profile in turn.
		for _, profileID := range profileIds {
			profChainName := ProfileChainName(profilePrefix, &types.ProfileID{Name: profileID}, r.nft)
			rules = append(rules,
				generictables.Rule{Match: r.NewMatch(), Action: r.Jump(profChainName)},
				// If policy marked packet as accepted, it returns, setting the
				// accept mark bit.  If that is set, return from this chain.
				generictables.Rule{
					Match:   r.NewMatch().MarkSingleBitSet(r.MarkAccept),
					Action:  r.Return(),
					Comment: []string{"Return if profile accepted"},
				})
		}

		// When rendering normal rules, if no profile marked the packet as accepted, drop
		// the packet.
		//
		// For untracked rules, we don't do that because there may be tracked rules
		// still to be applied to the packet in the filter table.
		// TODO (Matt): This (and the policy equivalent just above) can probably be refactored.
		//              At least the magic 1 and 2 need to be combined with the equivalent in CalculateActions.
		// No profile matched the packet: drop it.
		// if dropIfNoProfilesMatched {
		if r.FlowLogsEnabled {
			rules = append(rules, generictables.Rule{
				Match:  r.NewMatch(),
				Action: r.Nflog(nflogGroup, CalculateNoMatchProfileNFLOGPrefixStr(dir), 0),
			})
		}

		rules = append(rules, generictables.Rule{
			Match:   r.NewMatch(),
			Action:  r.IptablesFilterDenyAction(),
			Comment: []string{fmt.Sprintf("%s if no profiles matched", r.IptablesFilterDenyAction())},
		})
	}

	return &generictables.Chain{
		Name:  chainName,
		Rules: rules,
	}
}

func (r *DefaultRuleRenderer) appendConntrackRules(rules []generictables.Rule, allowAction generictables.Action) []generictables.Rule {
	// Allow return packets for established connections.
	if allowAction != (r.Allow()) {
		// If we've been asked to return instead of accept the packet immediately,
		// make sure we flag the packet as allowed.
		rules = append(rules,
			generictables.Rule{
				Match:  r.NewMatch().ConntrackState("RELATED,ESTABLISHED"),
				Action: r.SetMark(r.MarkAccept),
			},
		)
	}
	rules = append(rules,
		generictables.Rule{
			Match:  r.NewMatch().ConntrackState("RELATED,ESTABLISHED"),
			Action: allowAction,
		},
	)
	if !r.DisableConntrackInvalid {
		// Drop packets that aren't either a valid handshake or part of an established
		// connection.
		rules = append(rules, generictables.Rule{
			Match:  r.NewMatch().ConntrackState("INVALID"),
			Action: r.IptablesFilterDenyAction(),
		})
	}
	return rules
}

func EndpointChainName(prefix string, ifaceName string, maxLen int) string {
	return calicohash.GetLengthLimitedID(
		prefix,
		ifaceName,
		maxLen,
	)
}

// MaxPolicyGroupUIDLength is sized for UIDs to fit into their chain names.
const MaxPolicyGroupUIDLength = iptables.MaxChainNameLength - len(PolicyGroupInboundPrefix)

// PolicyGroup represents a sequence of one or more policies extracted from
// a list of policies.  If large enough (currently >1 entry) it will be
// programmed into its own chain.
type PolicyGroup struct {
	// Direction matches the policy model direction inbound/outbound. Each
	// group is either inbound or outbound since the set of active policy
	// can differ between the directions (a policy may have inbound rules
	// only, for example).
	Direction PolicyDirection

	Policies []*types.PolicyID

	// Selector is the original selector used by the grouped policies.  By
	// grouping on selector, we ensure that if one policy in a group matches
	// an endpoint then all policies in that group must match the endpoint.
	// Thus, two endpoint that share any policy in the group must share the
	// whole group.
	Selector string
	// cachedUID is the cached hash of the policy group details.  Filled in on
	// first call to UniqueID().
	cachedUID string
}

func (g *PolicyGroup) UniqueID() string {
	if g.cachedUID != "" {
		return g.cachedUID
	}

	hash := hash.Hash(sha3.New224())
	write := func(s string) {
		_, err := hash.Write([]byte(s))
		if err != nil {
			logrus.WithError(err).Panic("Failed to write to hasher")
		}
		_, err = hash.Write([]byte("\n"))
		if err != nil {
			logrus.WithError(err).Panic("Failed to write to hasher")
		}
	}
	write(g.Selector)
	write(fmt.Sprint(g.Direction))
	write(strconv.Itoa(len(g.Policies)))
	for _, policy := range g.Policies {
		write(policy.String())
	}
	hashBytes := hash.Sum(make([]byte, 0, hash.Size()))
	g.cachedUID = base64.RawURLEncoding.EncodeToString(hashBytes)[:MaxPolicyGroupUIDLength]
	return g.cachedUID
}

func (g *PolicyGroup) ChainName() string {
	if g.Direction == PolicyDirectionInbound {
		return PolicyGroupInboundPrefix + g.UniqueID()
	}
	return PolicyGroupOutboundPrefix + g.UniqueID()
}

func (g *PolicyGroup) ShouldBeInlined() bool {
	var count int
	for _, pol := range g.Policies {
		if !model.KindIsStaged(pol.Kind) {
			count++
			if count > 1 {
				return false
			}
		}
	}
	return true
}

func (g *PolicyGroup) HasNonStagedPolicies() bool {
	for _, pol := range g.Policies {
		if !model.KindIsStaged(pol.Kind) {
			return true
		}
	}
	return false
}

// PolicyGroupSliceStringer provides a String() method for a slice of
// PolicyGroup pointers.
type PolicyGroupSliceStringer []*PolicyGroup

func (p PolicyGroupSliceStringer) String() string {
	if p == nil {
		return "<nil>"
	}
	if len(p) == 0 {
		return "[]"
	}
	names := make([]string, len(p))
	for i, pg := range p {
		names[i] = pg.ChainName()
		if pg.ShouldBeInlined() {
			names[i] += "(inline)"
		}
	}
	return "[" + strings.Join(names, ",") + "]"
}

type TierPolicyGroupsStringer []TierPolicyGroups

func (tiers TierPolicyGroupsStringer) String() string {
	if tiers == nil {
		return "<nil>"
	}
	if len(tiers) == 0 {
		return "[]"
	}
	parts := make([]string, len(tiers))
	for i, t := range tiers {
		parts[i] = fmt.Sprintf("%s: Ingress:%s, Egress:%s",
			t.Name, PolicyGroupSliceStringer(t.IngressPolicies), PolicyGroupSliceStringer(t.EgressPolicies))
	}
	return "[" + strings.Join(parts, ",") + "]"
}
