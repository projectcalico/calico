// Copyright (c) 2017-2018 Tigera, Inc. All rights reserved.
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

	. "github.com/projectcalico/felix/iptables"
	"github.com/projectcalico/felix/proto"
	"github.com/projectcalico/felix/stringutils"
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

	result := []*Chain{}
	result = append(result,
		// Assemble a from-workload and to-workload dispatch chain.
		r.interfaceNameDispatchChains(
			names,
			WorkloadFromEndpointPfx,
			WorkloadToEndpointPfx,
			ChainFromWorkloadDispatch,
			ChainToWorkloadDispatch,
			true,
			true,
		)...,
	)

	return result
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
	applyOnForward bool,
) []*Chain {
	return r.hostDispatchChains(endpoints, false, applyOnForward)
}

func (r *DefaultRuleRenderer) FromHostDispatchChains(
	endpoints map[string]proto.HostEndpointID,
) []*Chain {
	return r.hostDispatchChains(endpoints, true, false)
}

func (r *DefaultRuleRenderer) hostDispatchChains(
	endpoints map[string]proto.HostEndpointID,
	fromOnly bool,
	applyOnForward bool,
) []*Chain {
	// Extract endpoint names.
	log.WithField("numEndpoints", len(endpoints)).Debug("Rendering host dispatch chains")
	names := make([]string, 0, len(endpoints))
	for ifaceName := range endpoints {
		names = append(names, ifaceName)
	}

	if fromOnly {
		return r.interfaceNameDispatchChains(
			names,
			HostFromEndpointPfx,
			"",
			ChainDispatchFromHostEndpoint,
			"",
			false,
			false,
		)
	}

	if !applyOnForward {
		return r.interfaceNameDispatchChains(
			names,
			HostFromEndpointPfx,
			HostToEndpointPfx,
			ChainDispatchFromHostEndpoint,
			ChainDispatchToHostEndpoint,
			false,
			false,
		)
	}

	return append(
		r.interfaceNameDispatchChains(
			names,
			HostFromEndpointPfx,
			HostToEndpointPfx,
			ChainDispatchFromHostEndpoint,
			ChainDispatchToHostEndpoint,
			false,
			false,
		),
		r.interfaceNameDispatchChains(
			names,
			HostFromEndpointForwardPfx,
			HostToEndpointForwardPfx,
			ChainDispatchFromHostEndPointForward,
			ChainDispatchToHostEndpointForward,
			false,
			false,
		)...,
	)
}

func (r *DefaultRuleRenderer) interfaceNameDispatchChains(
	names []string,
	fromEndpointPfx,
	toEndpointPfx,
	dispatchFromEndpointChainName,
	dispatchToEndpointChainName string,
	dropAtEndOfFromChain bool,
	dropAtEndOfToChain bool,
) []*Chain {

	log.WithField("ifaceNames", names).Debug("Rendering endpoint dispatch chains")

	// Since there can be >100 endpoints, putting them in a single list adds some latency to
	// endpoints that are later in the chain.  To reduce that impact, we build a shallow tree of
	// chains based on the prefixes of the chains.
	commonPrefix, prefixes, prefixToNames := r.sortAndDivideEndpointNamesToPrefixTree(names)

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
		dropAtEndOfFromChain,
	)

	chains := append(fromChildChains, fromRootChain)

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
			dropAtEndOfToChain,
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
				false,
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
			Action:  DropAction{},
			Comment: "Unknown endpoint",
		})
	}

	// At the end of set mark chain, set non-cali endpoint mark. A non-cali endpoint mark is used when a forward packet
	// whose incoming interface is neither a workload nor a host endpoint.
	rootSetMarkRules = append(rootSetMarkRules, Rule{
		Action: SetMaskedMarkAction{
			Mark: r.IptablesMarkNonCaliEndpoint,
			Mask: epMarkMapper.GetMask()},
		Comment: "Non-Cali endpoint mark",
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

	// Finalizing with a drop rule.
	log.Debug("Adding drop rules at end of root from mark chains.")
	rootFromMarkRules = append(rootFromMarkRules, Rule{
		Match:   Match(),
		Action:  DropAction{},
		Comment: "Unknown interface",
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
	dropAtEndOfChain bool,
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
				logCxt.WithField("ifaceName", name).Debug("Adding rule to child chains")

				childEndpointRules = append(childEndpointRules, Rule{
					Match:  getMatchForEndpoint(name),
					Action: getActionForEndpoint(endpointPfx, name),
				})
			}
			if dropAtEndOfChain {
				// Since we use a goto in the root chain (as described above), we
				// need to duplicate the drop rules at the end of the child chain
				// since packets that reach the end of the child chain would
				// return up past the root chain, appearing to be accepted.
				logCxt.Debug("Adding drop rules at end of child from chains.")
				childEndpointRules = append(childEndpointRules, Rule{
					Match:   Match(),
					Action:  DropAction{},
					Comment: "Unknown interface",
				})
			}

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

	if dropAtEndOfChain {
		log.Debug("Adding drop rules at end of root from chains.")
		rootRules = append(rootRules, Rule{
			Match:   Match(),
			Action:  DropAction{},
			Comment: "Unknown interface",
		})
	}

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
