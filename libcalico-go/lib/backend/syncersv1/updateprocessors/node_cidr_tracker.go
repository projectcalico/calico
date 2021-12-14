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

package updateprocessors

// nodeCIDRTracker can be used to keep track of CIDRs associated with each node,
// and to check when they have changed.
type nodeCIDRTracker struct {
	seenNodeCIDRs map[string][]string
}

func newNodeCIDRTracker() nodeCIDRTracker {
	return nodeCIDRTracker{
		seenNodeCIDRs: map[string][]string{},
	}
}

// SetNodeCIDRs updates the tracker with CIDRs for this node, and returns a list of
// CIDRs which are now out of date.
func (c *nodeCIDRTracker) SetNodeCIDRs(node string, cidrs []string) []string {
	// Find the outdated CIDRs based on the provided ones.
	outdated := c.findOutdatedCIDRs(node, cidrs)

	// Update internal state.
	if len(cidrs) == 0 {
		delete(c.seenNodeCIDRs, node)
	} else {
		c.seenNodeCIDRs[node] = cidrs
	}

	return outdated
}

func (c *nodeCIDRTracker) findOutdatedCIDRs(node string, currentCIDRs []string) []string {
	// Any that are in the old set of CIDRs but not the current set should be removed.
	toRemove := []string{}
	currentCIDRLookup := map[string]bool{}
	for _, current := range currentCIDRs {
		currentCIDRLookup[current] = true
	}
	for _, oldCIDR := range c.seenNodeCIDRs[node] {
		if _, ok := currentCIDRLookup[oldCIDR]; !ok {
			// Old CIDR is no longer in current CIDRs. Remove it.
			toRemove = append(toRemove, oldCIDR)
		}
	}
	return toRemove
}
