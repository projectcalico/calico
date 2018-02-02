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
	epMarkMapper EndpointMarkMapper,
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
		r.dispatchChains(
			names,
			epMarkMapper,
			WorkloadFromEndpointPfx,
			WorkloadToEndpointPfx,
			ChainFromWorkloadDispatch,
			ChainToWorkloadDispatch,
			true,
			true,
			false,
		)...,
	)

	if r.KubeIPVSSupportEnabled {
		// In some scenario, e.g. packet goes to an kuberentes ipvs service ip. Traffic goes through input/output filter chain
		// instead of forward filter chain. It is not feasible to match on an incoming workload interface with service ips.
		// Assemble a set-endpoint-mark chain to set the endpoint mark matching on the incoming workload interface and
		// a from-endpoint-mark chain to jump to a corresponding endpoint chain matching on its' endpoint mark.
		result = append(result,
			r.dispatchChains(
				names,
				epMarkMapper,
				WorkloadSetEndPointMarkPfx,
				WorkloadFromEndpointPfx,
				ChainDispatchSetEndPointMark,
				ChainDispatchFromEndPointMark,
				false, // Non forwarded packet will pass through set endpoint mark chain.
				true,
				true,
			)...,
		)
	}
	return result
}

func (r *DefaultRuleRenderer) HostDispatchChains(
	endpoints map[string]proto.HostEndpointID,
	epMarkMapper EndpointMarkMapper,
	applyOnForward bool,
) []*Chain {
	return r.hostDispatchChains(endpoints, epMarkMapper, false, applyOnForward)
}

func (r *DefaultRuleRenderer) FromHostDispatchChains(
	endpoints map[string]proto.HostEndpointID,
	epMarkMapper EndpointMarkMapper,
) []*Chain {
	return r.hostDispatchChains(endpoints, epMarkMapper, true, false)
}

func (r *DefaultRuleRenderer) hostDispatchChains(
	endpoints map[string]proto.HostEndpointID,
	epMarkMapper EndpointMarkMapper,
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
		return r.dispatchChains(
			names,
			epMarkMapper,
			HostFromEndpointPfx,
			"",
			ChainDispatchFromHostEndpoint,
			"",
			false,
			false,
			false,
		)
	}

	if !applyOnForward {
		return r.dispatchChains(
			names,
			epMarkMapper,
			HostFromEndpointPfx,
			HostToEndpointPfx,
			ChainDispatchFromHostEndpoint,
			ChainDispatchToHostEndpoint,
			false,
			false,
			false,
		)

	}

	return append(
		r.dispatchChains(
			names,
			epMarkMapper,
			HostFromEndpointPfx,
			HostToEndpointPfx,
			ChainDispatchFromHostEndpoint,
			ChainDispatchToHostEndpoint,
			false,
			false,
			false,
		),
		r.dispatchChains(
			names,
			epMarkMapper,
			HostFromEndpointForwardPfx,
			HostToEndpointForwardPfx,
			ChainDispatchFromHostEndPointForward,
			ChainDispatchToHostEndpointForward,
			false,
			false,
			false,
		)...,
	)
}

func (r *DefaultRuleRenderer) dispatchChains(
	names []string,
	epMarkMapper EndpointMarkMapper,
	fromEndpointPfx,
	toEndpointPfx,
	dispatchFromEndpointChainName,
	dispatchToEndpointChainName string,
	dropAtEndOfFromChain bool,
	dropAtEndOfToChain bool,
	useEndPointMark bool,
) []*Chain {
	// Sort interface names so that rules in the dispatch chain are ordered deterministically.
	// Otherwise we would reprogram the dispatch chain when there is no real change.
	sort.Strings(names)
	log.WithField("ifaceNames", names).Debug("Rendering dispatch chains")

	// Since there can be >100 endpoints, putting them in a single list adds some latency to
	// endpoints that are later in the chain.  To reduce that impact, we build a shallow tree of
	// chains based on the prefixes of the chains.

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
			log.Panic("Unable to render dispatch chain. Empty interface name.")
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

	rootFromEndpointRules := make([]Rule, 0)
	rootToEndpointRules := make([]Rule, 0)

	// Now, iterate over the prefixes.  If there are multiple names in a prefix, we render a
	// child chain for that prefix.  Otherwise, we render the rule directly to avoid the cost
	// of an extra goto. Note we need to deal with from-endpoint-mark as to-endpoint-chain.
	var chains []*Chain
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
			childFromChainName := dispatchFromEndpointChainName + "-" + nextChar
			childToChainName := dispatchToEndpointChainName + "-" + nextChar
			logCxt := logCxt.WithFields(log.Fields{
				"childFromChainName": childFromChainName,
				"childToChainName":   childToChainName,
				"ifaceMatch":         ifaceMatch,
			})
			logCxt.Debug("Multiple interfaces with prefix, rendering child chain")
			rootFromEndpointRules = append(rootFromEndpointRules, Rule{
				Match: Match().InInterface(ifaceMatch),
				// Note: we use a goto here, which means that packets will not
				// return to this chain.  This prevents packets from traversing the
				// rest of the root chain once we've found their prefix.
				Action: GotoAction{
					Target: childFromChainName,
				},
			})

			if !useEndPointMark {
				rootToEndpointRules = append(rootToEndpointRules, Rule{
					Match: Match().OutInterface(ifaceMatch),
					Action: GotoAction{
						Target: childToChainName,
					},
				})
			}

			// ...and child chains.
			childFromEndpointRules := make([]Rule, 0)
			childToEndpointRules := make([]Rule, 0)
			for _, name := range ifaceNames {
				logCxt.WithField("ifaceName", name).Debug("Adding rule to child chains")

				childFromEndpointRules = append(childFromEndpointRules, Rule{
					Match: Match().InInterface(name),
					Action: GotoAction{
						Target: EndpointChainName(fromEndpointPfx, name),
					},
				})

				if !useEndPointMark {
					childToEndpointRules = append(childToEndpointRules, Rule{
						Match: Match().OutInterface(name),
						Action: GotoAction{
							Target: EndpointChainName(toEndpointPfx, name),
						},
					})
				} else if endPointMark, err := epMarkMapper.GetEndpointMark(name); err == nil {
					// implement each name into root rules for from-endpoint-mark chain.
					rootToEndpointRules = append(rootToEndpointRules, Rule{
						Match: Match().MarkMatchesWithMask(endPointMark, epMarkMapper.GetMask()),
						Action: GotoAction{
							Target: EndpointChainName(toEndpointPfx, name),
						},
					})
				}
			}
			if dropAtEndOfFromChain {
				// Since we use a goto in the root chain (as described above), we
				// need to duplicate the drop rules at the end of the child chain
				// since packets that reach the end of the child chain would
				// return up past the root chain, appearing to be accepted.
				logCxt.Debug("Adding drop rules at end of child from chains.")
				childFromEndpointRules = append(childFromEndpointRules, Rule{
					Match:   Match(),
					Action:  DropAction{},
					Comment: "Unknown interface",
				})
			}

			if dropAtEndOfToChain {
				logCxt.Debug("Adding drop rules at end of child to chains.")
				childToEndpointRules = append(childToEndpointRules, Rule{
					Match:   Match(),
					Action:  DropAction{},
					Comment: "Unknown interface",
				})
			}

			childFromEndpointChain := &Chain{
				Name:  childFromChainName,
				Rules: childFromEndpointRules,
			}
			childToEndpointChain := &Chain{
				Name:  childToChainName,
				Rules: childToEndpointRules,
			}
			if toEndpointPfx != "" && !useEndPointMark {
				chains = append(chains, childFromEndpointChain, childToEndpointChain)
			} else {
				// Only emit from endpoint chains.
				chains = append(chains, childFromEndpointChain)
			}
		} else {
			// Only one name with this prefix, render rules directly into the root
			// chains.
			ifaceName := ifaceNames[0]
			logCxt.WithField("ifaceName", ifaceName).Debug("Adding rule to root chains")

			rootFromEndpointRules = append(rootFromEndpointRules, Rule{
				Match: Match().InInterface(ifaceName),
				Action: GotoAction{
					Target: EndpointChainName(fromEndpointPfx, ifaceName),
				},
			})

			if !useEndPointMark {
				rootToEndpointRules = append(rootToEndpointRules, Rule{
					Match: Match().OutInterface(ifaceName),
					Action: GotoAction{
						Target: EndpointChainName(toEndpointPfx, ifaceName),
					},
				})
			} else if endPointMark, err := epMarkMapper.GetEndpointMark(ifaceName); err == nil {
				rootToEndpointRules = append(rootToEndpointRules, Rule{
					Match: Match().MarkMatchesWithMask(endPointMark, epMarkMapper.GetMask()),
					Action: GotoAction{
						Target: EndpointChainName(toEndpointPfx, ifaceName),
					},
				})

			}
		}
	}

	if dropAtEndOfFromChain {
		log.Debug("Adding drop rules at end of root from chains.")
		rootFromEndpointRules = append(rootFromEndpointRules, Rule{
			Match:   Match(),
			Action:  DropAction{},
			Comment: "Unknown interface",
		})
	}

	if dropAtEndOfToChain {
		log.Debug("Adding drop rules at end of root to chains.")
		rootToEndpointRules = append(rootToEndpointRules, Rule{
			Match:   Match(),
			Action:  DropAction{},
			Comment: "Unknown interface",
		})
	}

	fromEndpointDispatchChain := &Chain{
		Name:  dispatchFromEndpointChainName,
		Rules: rootFromEndpointRules,
	}
	toEndpointDispatchChain := &Chain{
		Name:  dispatchToEndpointChainName,
		Rules: rootToEndpointRules,
	}
	if toEndpointPfx != "" {
		chains = append(chains, fromEndpointDispatchChain, toEndpointDispatchChain)
	} else {
		// Only emit from endpoint chains.
		chains = append(chains, fromEndpointDispatchChain)
	}

	return chains
}
