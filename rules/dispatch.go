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
		r.dispatchEndpointChains(
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

// In some scenario, e.g. packet goes to an kuberentes ipvs service ip. Traffic goes through input/output filter chain
// instead of forward filter chain. It is not feasible to match on an incoming workload/host interface with service ips.
// Assemble a set-endpoint-mark chain to set the endpoint mark matching on the incoming workload/host interface and
// a from-endpoint-mark chain to jump to a corresponding endpoint chain matching on its' endpoint mark.
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

	return r.dispatchEndPointMarkChains(
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
		return r.dispatchEndpointChains(
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
		return r.dispatchEndpointChains(
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
		r.dispatchEndpointChains(
			names,
			HostFromEndpointPfx,
			HostToEndpointPfx,
			ChainDispatchFromHostEndpoint,
			ChainDispatchToHostEndpoint,
			false,
			false,
		),
		r.dispatchEndpointChains(
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

func (r *DefaultRuleRenderer) dispatchEndpointChains(
	names []string,
	fromEndpointPfx,
	toEndpointPfx,
	dispatchFromEndpointChainName,
	dispatchToEndpointChainName string,
	dropAtEndOfFromChain bool,
	dropAtEndOfToChain bool,
) []*Chain {
	// Sort interface names so that rules in the dispatch chain are ordered deterministically.
	// Otherwise we would reprogram the dispatch chain when there is no real change.
	sort.Strings(names)
	log.WithField("ifaceNames", names).Debug("Rendering endpoint dispatch chains")

	// Since there can be >100 endpoints, putting them in a single list adds some latency to
	// endpoints that are later in the chain.  To reduce that impact, we build a shallow tree of
	// chains based on the prefixes of the chains.
	commonPrefix, prefixes, prefixToNames := r.divideEndpointNamesToPrefixTree(names)

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

			rootToEndpointRules = append(rootToEndpointRules, Rule{
				Match: Match().OutInterface(ifaceMatch),
				Action: GotoAction{
					Target: childToChainName,
				},
			})

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

				childToEndpointRules = append(childToEndpointRules, Rule{
					Match: Match().OutInterface(name),
					Action: GotoAction{
						Target: EndpointChainName(toEndpointPfx, name),
					},
				})
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
			if toEndpointPfx != "" {
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

			rootToEndpointRules = append(rootToEndpointRules, Rule{
				Match: Match().OutInterface(ifaceName),
				Action: GotoAction{
					Target: EndpointChainName(toEndpointPfx, ifaceName),
				},
			})
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

func (r *DefaultRuleRenderer) dispatchEndPointMarkChains(
	wlNames []string,
	hepNames []string,
	epMarkMapper EndpointMarkMapper,
	setMarkPfx,
	wlFromMarkPfx,
	hepFromMarkPfx,
	dispatchSetMarkEndpointChainName,
	dispatchFromMarkEndpointChainName string,
) []*Chain {
	names := append(wlNames, hepNames...)
	// Sort interface names so that rules in the dispatch chain are ordered deterministically.
	// Otherwise we would reprogram the dispatch chain when there is no real change.
	sort.Strings(names)
	log.WithField("ifaceNames", names).Debug("Rendering endpoint mark dispatch chains")

	rootSetMarkRules := make([]Rule, 0)
	rootFromMarkRules := make([]Rule, 0)

	// start rendering set mark rules.
	// Since there can be >100 endpoints, putting them in a single list adds some latency to
	// endpoints that are later in the chain.  To reduce that impact, we build a shallow tree of
	// chains based on the prefixes of the chains.
	commonPrefix, prefixes, prefixToNames := r.divideEndpointNamesToPrefixTree(names)

	// Now, iterate over the prefixes.  If there are multiple names in a prefix, we render a
	// child chain for that prefix.  Otherwise, we render the rule directly to avoid the cost
	// of an extra goto.
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
			childSetMarkChainName := dispatchSetMarkEndpointChainName + "-" + nextChar
			logCxt := logCxt.WithFields(log.Fields{
				"childSetMarkChainName": childSetMarkChainName,
				"ifaceMatch":            ifaceMatch,
			})
			logCxt.Debug("Multiple interfaces with prefix, rendering child chain")
			rootSetMarkRules = append(rootSetMarkRules, Rule{
				Match: Match().InInterface(ifaceMatch),
				// Note: we use a goto here, which means that packets will not
				// return to this chain.  This prevents packets from traversing the
				// rest of the root chain once we've found their prefix.
				Action: GotoAction{
					Target: childSetMarkChainName,
				},
			})

			// ...and child chains.
			childSetMarkEndpointRules := make([]Rule, 0)
			for _, name := range ifaceNames {
				logCxt.WithField("ifaceName", name).Debug("Adding rule to child chains")

				childSetMarkEndpointRules = append(childSetMarkEndpointRules, Rule{
					Match: Match().InInterface(name),
					Action: GotoAction{
						Target: EndpointChainName(setMarkPfx, name),
					},
				})
			}

			childSetMarkEndpointChain := &Chain{
				Name:  childSetMarkChainName,
				Rules: childSetMarkEndpointRules,
			}

			chains = append(chains, childSetMarkEndpointChain)

		} else {
			// Only one name with this prefix, render rules directly into the root
			// chains.
			ifaceName := ifaceNames[0]
			logCxt.WithField("ifaceName", ifaceName).Debug("Adding rule to root chains")

			rootSetMarkRules = append(rootSetMarkRules, Rule{
				Match: Match().InInterface(ifaceName),
				Action: GotoAction{
					Target: EndpointChainName(setMarkPfx, ifaceName),
				},
			})
		}
	}

	// At the end of set mark chain, set generic endpoint mark. A generic endpoint mark is used when a forward packet
	// whose incoming interface is neither a workload nor a host endpoint.
	rootSetMarkRules = append(rootSetMarkRules, Rule{
		Action: SetMaskedMarkAction{
			Mark: r.IptablesMarkEndpointGeneric,
			Mask: epMarkMapper.GetMask()},
		Comment: "Generic endpoint mark",
	})

	// start rendering from mark rules.
	// Rendering rules for workload endpoints.
	for _, name := range wlNames {
		if endPointMark, err := epMarkMapper.GetEndpointMark(name); err == nil {
			// implement each name into root rules for from-endpoint-mark chain.
			log.WithField("ifaceName", name).Debug("Adding rule to from mark chain")
			rootFromMarkRules = append(rootFromMarkRules, Rule{
				Match: Match().MarkMatchesWithMask(endPointMark, epMarkMapper.GetMask()),
				Action: GotoAction{
					Target: EndpointChainName(wlFromMarkPfx, name),
				},
			})
		}
	}

	// Rendering rules for host endpoints.
	for _, name := range hepNames {
		if endPointMark, err := epMarkMapper.GetEndpointMark(name); err == nil {
			// implement each name into root rules for from-endpoint-mark chain.
			log.WithField("ifaceName", name).Debug("Adding rule to from mark chain")
			rootFromMarkRules = append(rootFromMarkRules, Rule{
				Match: Match().MarkMatchesWithMask(endPointMark, epMarkMapper.GetMask()),
				Action: GotoAction{
					Target: EndpointChainName(hepFromMarkPfx, name),
				},
			})
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

// Divide endpoint names into shallow tree.
// Return common prefix, list of prefix and map of prefix to list of interface names.
func (r *DefaultRuleRenderer) divideEndpointNamesToPrefixTree(names []string) (string, []string, map[string][]string) {
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
