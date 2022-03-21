// Copyright (c) 2017-2020 Tigera, Inc. All rights reserved.
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
	"sort"

	log "github.com/sirupsen/logrus"

	. "github.com/projectcalico/calico/felix/iptables"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/stringutils"
)

func (r *DefaultRuleRenderer) WorkloadDispatchChains(
	endpoints map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint,
) []*Chain {
	// Extract endpoint names.
	log.WithField("numEndpoints", len(endpoints)).Debug("Rendering workload dispatch chains")
	names := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		names = append(names, endpoint.Name)
	}

	// If there is no policy at all for a workload endpoint, we don't allow any traffic through
	// it.
	endRules := []Rule{
		Rule{
			Match:   Match(),
			Action:  r.DropActionOverride,
			Comment: []string{"Unknown interface"},
		},
	}
	return r.interfaceNameDispatchChains(
		names,
		WorkloadFromEndpointPfx,
		WorkloadToEndpointPfx,
		ChainFromWorkloadDispatch,
		ChainToWorkloadDispatch,
		endRules,
		endRules,
	)
}

func (r *DefaultRuleRenderer) WorkloadInterfaceAllowChains(
	endpoints map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint,
) []*Chain {
	// Extract endpoint names.
	log.WithField("numEndpoints", len(endpoints)).Debug("Rendering workload interface allow chain")
	names := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		names = append(names, endpoint.Name)
	}

	// If workload endpoint is unknown, drop.
	endRules := []Rule{
		{
			Match:   Match(),
			Action:  r.DropActionOverride,
			Comment: []string{"Unknown interface"},
		},
	}

	// Since there can be >100 endpoints, putting them in a single list adds some latency to
	// endpoints that are later in the chain.  To reduce that impact, we build a shallow tree of
	// chains based on the prefixes of the chains.
	commonPrefix, prefixes, prefixToNames := r.sortAndDivideEndpointNamesToPrefixTree(names)
	var chains []*Chain
	// Build to endpoint chains.
	toChildChains, toRootChain, _ := r.buildSingleDispatchChains(
		ChainToWorkloadDispatch,
		commonPrefix,
		prefixes,
		prefixToNames,
		WorkloadPfxSpecialAllow,
		func(name string) MatchCriteria { return Match().OutInterface(name) },
		func(pfx, name string) Action {
			return AcceptAction{}
		},
		endRules,
	)
	chains = append(chains, toChildChains...)
	chains = append(chains, toRootChain)

	return chains
}

// In some scenario, e.g. packet goes to an kubernetes ipvs service ip. Traffic goes through input/output filter chain
// instead of forward filter chain. It is not feasible to match on an incoming workload/host interface with service ips.
// Assemble a set-endpoint-mark chain to set the endpoint mark matching on the incoming workload/host interface and
// a from-endpoint-mark chain to jump to a corresponding endpoint chain matching on its endpoint mark.
func (r *DefaultRuleRenderer) EndpointMarkDispatchChains(
	epMarkMapper EndpointMarkMapper,
	wlEndpoints map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint,
	hepEndpoints map[string]proto.HostEndpointID,
) []*Chain {
	// Extract endpoint names.
	logCxt := log.WithFields(log.Fields{
		"numWorkloadEndpoint": len(wlEndpoints),
		"numHostEndpoint":     len(hepEndpoints),
	})
	logCxt.Debug("Rendering endpoint mark dispatch chains")
	wlNames := make([]string, 0, len(wlEndpoints))
	for _, endpoint := range wlEndpoints {
		wlNames = append(wlNames, endpoint.Name)
	}
	hepNames := make([]string, 0, len(hepEndpoints))
	for ifaceName := range hepEndpoints {
		hepNames = append(hepNames, ifaceName)
	}

	return r.endpointMarkDispatchChains(
		wlNames,
		hepNames,
		epMarkMapper,
		SetEndPointMarkPfx,
		WorkloadFromEndpointPfx,
		HostFromEndpointForwardPfx,
		ChainDispatchSetEndPointMark,
		ChainDispatchFromEndPointMark,
	)
}

func (r *DefaultRuleRenderer) HostDispatchChains(
	endpoints map[string]proto.HostEndpointID,
	defaultIfaceName string,
	applyOnForward bool,
) []*Chain {
	return r.hostDispatchChains(endpoints, defaultIfaceName, "to+from", applyOnForward)
}

// For pre-DNAT policy, which only applies on ingress from a host endpoint.
func (r *DefaultRuleRenderer) FromHostDispatchChains(
	endpoints map[string]proto.HostEndpointID,
	defaultIfaceName string,
) []*Chain {
	return r.hostDispatchChains(endpoints, defaultIfaceName, "from", false)
}

// For applying normal host endpoint egress policy to traffic from the host which has been DNAT'd.
func (r *DefaultRuleRenderer) ToHostDispatchChains(
	endpoints map[string]proto.HostEndpointID,
	defaultIfaceName string,
) []*Chain {
	return r.hostDispatchChains(endpoints, defaultIfaceName, "to", false)
}

func (r *DefaultRuleRenderer) hostDispatchChains(
	endpoints map[string]proto.HostEndpointID,
	defaultIfaceName string,
	directions string,
	applyOnForward bool,
) []*Chain {
	// Extract endpoint names.
	log.WithField("numEndpoints", len(endpoints)).Debug("Rendering host dispatch chains")
	names := make([]string, 0, len(endpoints))
	for ifaceName := range endpoints {
		names = append(names, ifaceName)
	}

	var fromEndRules, toEndRules, fromEndForwardRules, toEndForwardRules []Rule

	if defaultIfaceName != "" {
		// Arrange sets of rules to goto the specified default chain for any packets that don't match an
		// interface in the `endpoints` map.
		fromEndRules = []Rule{
			Rule{
				Action: GotoAction{Target: EndpointChainName(HostFromEndpointPfx, defaultIfaceName)},
			},
		}
		fromEndForwardRules = []Rule{
			Rule{
				Action: GotoAction{Target: EndpointChainName(HostFromEndpointForwardPfx, defaultIfaceName)},
			},
		}

		// For traffic from the host to a host endpoint, we only use the default chain -
		// i.e. policy applying to the wildcard HEP - when we're egressing through a
		// fabric-facing interface.  We never apply wildcard HEP normal policy for traffic
		// going to a local workload.
		if !applyOnForward {
			for _, prefix := range r.WorkloadIfacePrefixes {
				ifaceMatch := prefix + "+"
				toEndRules = append(toEndRules, Rule{
					Match:   Match().OutInterface(ifaceMatch),
					Action:  ReturnAction{},
					Comment: []string{"Skip egress WHEP policy for traffic to local workload"},
				})
			}
		}

		toEndRules = append(toEndRules, Rule{
			Action: GotoAction{Target: EndpointChainName(HostToEndpointPfx, defaultIfaceName)},
		})
		toEndForwardRules = []Rule{
			Rule{
				Action: GotoAction{Target: EndpointChainName(HostToEndpointForwardPfx, defaultIfaceName)},
			},
		}
	}

	if directions == "from" {
		return r.interfaceNameDispatchChains(
			names,
			HostFromEndpointPfx,
			"",
			ChainDispatchFromHostEndpoint,
			"",
			fromEndRules,
			toEndRules,
		)
	}

	if directions == "to" {
		return r.interfaceNameDispatchChains(
			names,
			"",
			HostToEndpointPfx,
			"",
			ChainDispatchToHostEndpoint,
			fromEndRules,
			toEndRules,
		)
	}

	if !applyOnForward {
		return r.interfaceNameDispatchChains(
			names,
			HostFromEndpointPfx,
			HostToEndpointPfx,
			ChainDispatchFromHostEndpoint,
			ChainDispatchToHostEndpoint,
			fromEndRules,
			toEndRules,
		)
	}

	return append(
		r.interfaceNameDispatchChains(
			names,
			HostFromEndpointPfx,
			HostToEndpointPfx,
			ChainDispatchFromHostEndpoint,
			ChainDispatchToHostEndpoint,
			fromEndRules,
			toEndRules,
		),
		r.interfaceNameDispatchChains(
			names,
			HostFromEndpointForwardPfx,
			HostToEndpointForwardPfx,
			ChainDispatchFromHostEndPointForward,
			ChainDispatchToHostEndpointForward,
			fromEndForwardRules,
			toEndForwardRules,
		)...,
	)
}

func (r *DefaultRuleRenderer) interfaceNameDispatchChains(
	names []string,
	fromEndpointPfx,
	toEndpointPfx,
	dispatchFromEndpointChainName,
	dispatchToEndpointChainName string,
	fromEndRules []Rule,
	toEndRules []Rule,
) (chains []*Chain) {

	log.WithField("ifaceNames", names).Debug("Rendering endpoint dispatch chains")

	// Since there can be >100 endpoints, putting them in a single list adds some latency to
	// endpoints that are later in the chain.  To reduce that impact, we build a shallow tree of
	// chains based on the prefixes of the chains.
	commonPrefix, prefixes, prefixToNames := r.sortAndDivideEndpointNamesToPrefixTree(names)

	if fromEndpointPfx != "" {
		// Build from endpoint chains.
		fromChildChains, fromRootChain, _ := r.buildSingleDispatchChains(
			dispatchFromEndpointChainName,
			commonPrefix,
			prefixes,
			prefixToNames,
			fromEndpointPfx,
			func(name string) MatchCriteria { return Match().InInterface(name) },
			func(pfx, name string) Action {
				return GotoAction{
					Target: EndpointChainName(pfx, name),
				}
			},
			fromEndRules,
		)
		chains = append(chains, fromChildChains...)
		chains = append(chains, fromRootChain)
	}

	if toEndpointPfx != "" {
		// Build to endpoint chains.
		toChildChains, toRootChain, _ := r.buildSingleDispatchChains(
			dispatchToEndpointChainName,
			commonPrefix,
			prefixes,
			prefixToNames,
			toEndpointPfx,
			func(name string) MatchCriteria { return Match().OutInterface(name) },
			func(pfx, name string) Action {
				return GotoAction{
					Target: EndpointChainName(pfx, name),
				}
			},
			toEndRules,
		)
		chains = append(chains, toChildChains...)
		chains = append(chains, toRootChain)
	}

	return chains
}

func (r *DefaultRuleRenderer) endpointMarkDispatchChains(
	wlNames []string,
	hepNames []string,
	epMarkMapper EndpointMarkMapper,
	setMarkPfx,
	wlFromMarkPfx,
	hepFromMarkPfx,
	dispatchSetMarkEndpointChainName,
	dispatchFromMarkEndpointChainName string,
) []*Chain {

	log.WithField("ifaceNames", append(wlNames, hepNames...)).Debug("Rendering endpoint mark dispatch chains")

	// start rendering set mark rules.
	rootSetMarkRules := make([]Rule, 0)
	chains := make([]*Chain, 0)

	// Since there can be >100 endpoints, putting them in a single list adds some latency to
	// endpoints that are later in the chain.  To reduce that impact, we build a shallow tree of
	// chains based on the prefixes of the chains.

	// The workload and host endpoint share the same root chain. We also need to put an non-cali mark rules at the end.
	// Work out child chains and root rules for workload and host endpoint separately and merge them back together.
	for _, names := range [][]string{wlNames, hepNames} {
		if len(names) > 0 {
			commonPrefix, prefixes, prefixToNames := r.sortAndDivideEndpointNamesToPrefixTree(names)

			childChains, _, rootRules := r.buildSingleDispatchChains(
				dispatchSetMarkEndpointChainName,
				commonPrefix,
				prefixes,
				prefixToNames,
				setMarkPfx,
				func(name string) MatchCriteria { return Match().InInterface(name) },
				func(pfx, name string) Action {
					return GotoAction{
						Target: EndpointChainName(pfx, name),
					}
				},
				nil,
			)

			chains = append(chains, childChains...)
			rootSetMarkRules = append(rootSetMarkRules, rootRules...)
		}
	}

	// If a packet has an incoming interface as calixxx or tapxxx,
	// but felix has not yet got an endpoint for it, drop packet.
	// For instance, cni created a pod but felix has not got the workload endpoint update yet.
	for _, prefix := range r.WorkloadIfacePrefixes {
		ifaceMatch := prefix + "+"
		rootSetMarkRules = append(rootSetMarkRules, Rule{
			Match:   Match().InInterface(ifaceMatch),
			Action:  r.DropActionOverride,
			Comment: []string{"Unknown endpoint"},
		})
	}

	// At the end of set mark chain, set non-cali endpoint mark. A non-cali endpoint mark is used when a forward packet
	// whose incoming interface is neither a workload nor a host endpoint.
	rootSetMarkRules = append(rootSetMarkRules, Rule{
		Action: SetMaskedMarkAction{
			Mark: r.IptablesMarkNonCaliEndpoint,
			Mask: epMarkMapper.GetMask()},
		Comment: []string{"Non-Cali endpoint mark"},
	})

	// start rendering from mark rules for workload and host endpoints.
	rootFromMarkRules := make([]Rule, 0)

	fromMarkPrefixes := []string{wlFromMarkPfx, hepFromMarkPfx}
	for index, names := range [][]string{wlNames, hepNames} {
		// Rendering rules for endpoints.
		sort.Strings(names)
		lastName := ""
		for _, name := range names {
			if name == lastName {
				log.WithField("ifaceName", name).Error(
					"Multiple endpoints with same interface name detected. " +
						"Incorrect policy may be applied.")
				continue
			}
			if endPointMark, err := epMarkMapper.GetEndpointMark(name); err == nil {
				// implement each name into root rules for from-endpoint-mark chain.
				log.WithField("ifaceName", name).Debug("Adding rule to from mark chain")
				rootFromMarkRules = append(rootFromMarkRules, Rule{
					Match: Match().MarkMatchesWithMask(endPointMark, epMarkMapper.GetMask()),
					Action: GotoAction{
						Target: EndpointChainName(fromMarkPrefixes[index], name),
					},
				})
			}
			lastName = name
		}
	}

	// Finalizing with a drop/reject rule.
	log.Debugf("Adding %s rules at end of root from mark chains.", r.DropActionOverride)
	rootFromMarkRules = append(rootFromMarkRules, Rule{
		Match:   Match(),
		Action:  r.DropActionOverride,
		Comment: []string{"Unknown interface"},
	})

	// return set mark and from mark chains.
	setMarkDispatchChain := &Chain{
		Name:  dispatchSetMarkEndpointChainName,
		Rules: rootSetMarkRules,
	}
	fromMarkDispatchChain := &Chain{
		Name:  dispatchFromMarkEndpointChainName,
		Rules: rootFromMarkRules,
	}
	chains = append(chains, setMarkDispatchChain, fromMarkDispatchChain)

	return chains
}

// Build a single dispatch chains for an endpoint based on prefixes.
// Return child chains, root chain and root rules of root chain.
func (r *DefaultRuleRenderer) buildSingleDispatchChains(
	chainName string,
	commonPrefix string,
	prefixes []string,
	prefixToNames map[string][]string,
	endpointPfx string,
	getMatchForEndpoint func(name string) MatchCriteria,
	getActionForEndpoint func(pfx, name string) Action,
	endRules []Rule,
) ([]*Chain, *Chain, []Rule) {

	childChains := make([]*Chain, 0)
	rootRules := make([]Rule, 0)

	// Now, iterate over the prefixes.  If there are multiple names in a prefix, we render a
	// child chain for that prefix.  Otherwise, we render the rule directly to avoid the cost
	// of an extra goto.
	for _, prefix := range prefixes {
		ifaceNames := prefixToNames[prefix]
		logCxt := log.WithFields(log.Fields{
			"prefix":          prefix,
			"namesWithPrefix": ifaceNames,
		})
		logCxt.Debug("Considering prefix")
		if len(ifaceNames) > 1 {
			// More than one name, render a prefix match in the root chain...
			nextChar := prefix[len(commonPrefix):]
			ifaceMatch := prefix + "+"
			childChainName := chainName + "-" + nextChar
			logCxt := logCxt.WithFields(log.Fields{
				"childChainName": childChainName,
				"ifaceMatch":     ifaceMatch,
			})
			logCxt.Debug("Multiple interfaces with prefix, rendering child chain")
			rootRules = append(rootRules, Rule{
				Match: getMatchForEndpoint(ifaceMatch),
				// Note: we use a goto here, which means that packets will not
				// return to this chain.  This prevents packets from traversing the
				// rest of the root chain once we've found their prefix.
				Action: GotoAction{
					Target: childChainName,
				},
			})

			// ...and child chains.
			childEndpointRules := make([]Rule, 0)
			for _, name := range ifaceNames {
				logCxt.WithField("ifaceName", name).Debug("Adding rule to child chain")

				childEndpointRules = append(childEndpointRules, Rule{
					Match:  getMatchForEndpoint(name),
					Action: getActionForEndpoint(endpointPfx, name),
				})
			}

			// Since we use a goto in the root chain (as described above), we need to
			// duplicate the end rules at the end of the child chain so that
			// non-matching packets in a child chain are treated the same as
			// non-matching packets in the root chain.
			logCxt.Debug("Adding end rules at end of child chain")
			childEndpointRules = append(childEndpointRules, endRules...)

			childEndpointChain := &Chain{
				Name:  childChainName,
				Rules: childEndpointRules,
			}

			childChains = append(childChains, childEndpointChain)

		} else {
			// Only one name with this prefix, render rules directly into the root
			// chains.
			ifaceName := ifaceNames[0]
			logCxt.WithField("ifaceName", ifaceName).Debug("Adding rule to root chains")

			rootRules = append(rootRules, Rule{
				Match:  getMatchForEndpoint(ifaceName),
				Action: getActionForEndpoint(endpointPfx, ifaceName),
			})
		}
	}

	log.Debug("Adding end rules at end of root chain")
	rootRules = append(rootRules, endRules...)

	rootChain := &Chain{
		Name:  chainName,
		Rules: rootRules,
	}

	return childChains, rootChain, rootRules
}

// Divide endpoint names into shallow tree.
// Return common prefix, list of prefix and map of prefix to list of interface names.
func (r *DefaultRuleRenderer) sortAndDivideEndpointNamesToPrefixTree(names []string) (string, []string, map[string][]string) {
	// Sort interface names so that rules in the dispatch chain are ordered deterministically.
	// Otherwise we would reprogram the dispatch chain when there is no real change.
	sort.Strings(names)

	// Start by figuring out the common prefix of the endpoint names.  Commonly, this will
	// be the interface prefix, e.g. "cali", but we may get lucky if multiple interfaces share
	// a longer prefix.
	commonPrefix := stringutils.CommonPrefix(names)
	log.WithField("commonPrefix", commonPrefix).Debug("Calculated common prefix")

	// Then, divide the names into bins based on their next character.
	prefixes := []string{}
	prefixToNames := map[string][]string{}
	lastName := ""
	for _, name := range names {
		if name == "" {
			log.Panic("Unable to divide endpoint names. Empty interface name.")
		}
		if name == lastName {
			log.WithField("ifaceName", name).Error(
				"Multiple endpoints with same interface name detected. " +
					"Incorrect policy may be applied.")
			continue
		}
		prefix := commonPrefix
		if len(name) > len(commonPrefix) {
			prefix = name[:len(commonPrefix)+1]
		}
		if _, present := prefixToNames[prefix]; !present {
			// Record the prefixes in sorted order (if we iterate over the map, we get a
			// random order, which we don't want).
			prefixes = append(prefixes, prefix)
		}
		prefixToNames[prefix] = append(prefixToNames[prefix], name)
		lastName = name
	}

	return commonPrefix, prefixes, prefixToNames
}
