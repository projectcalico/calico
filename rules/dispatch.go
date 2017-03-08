// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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

	log "github.com/Sirupsen/logrus"

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

	return r.dispatchChains(
		names,
		WorkloadFromEndpointPfx,
		WorkloadToEndpointPfx,
		ChainFromWorkloadDispatch,
		ChainToWorkloadDispatch,
		true,
	)
}

func (r *DefaultRuleRenderer) HostDispatchChains(
	endpoints map[string]proto.HostEndpointID,
) []*Chain {

	// Extract endpoint names.
	log.WithField("numEndpoints", len(endpoints)).Debug("Rendering host dispatch chains")
	names := make([]string, 0, len(endpoints))
	for ifaceName := range endpoints {
		names = append(names, ifaceName)
	}

	return r.dispatchChains(
		names,
		HostFromEndpointPfx,
		HostToEndpointPfx,
		ChainDispatchFromHostEndpoint,
		ChainDispatchToHostEndpoint,
		false,
	)
}

func (r *DefaultRuleRenderer) dispatchChains(
	names []string,
	fromEndpointPfx,
	toEndpointPfx,
	dispatchFromEndpointChainName,
	dispatchToEndpointChainName string,
	dropAtEndOfChain bool,
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
			if dropAtEndOfChain {
				// Since we use a goto in the root chain (as described above), we
				// need to duplicate the drop rules at the end of the child chain
				// since packets that reach the end of the child chain would
				// return up past the root chain, appearing to be accepted.
				logCxt.Debug("Adding drop rules at end of child chains.")
				childFromEndpointRules = append(childFromEndpointRules, Rule{
					Match:   Match(),
					Action:  DropAction{},
					Comment: "Unknown interface",
				})
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
			chains = append(chains, childFromEndpointChain, childToEndpointChain)
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

	if dropAtEndOfChain {
		log.Debug("Adding drop rules at end of root chains.")
		rootFromEndpointRules = append(rootFromEndpointRules, Rule{
			Match:   Match(),
			Action:  DropAction{},
			Comment: "Unknown interface",
		})
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
	chains = append(chains, fromEndpointDispatchChain, toEndpointDispatchChain)

	return chains
}
