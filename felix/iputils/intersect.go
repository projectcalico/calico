// Copyright (c) 2018-2020 Tigera, Inc. All rights reserved.
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

package iputils

import (
	"sort"

	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

func IntersectCIDRs(aStrs []string, bStrs []string) (out []string) {
	aCIDRs := parseCIDRs(aStrs)
	bCIDRs := parseCIDRs(bStrs)

	intersection := set.NewBoxed[ip.CIDR]()

	for _, a := range aCIDRs {
		for _, b := range bCIDRs {
			if a.Prefix() == b.Prefix() {
				// Same length prefix, compare IPs.
				if a.Addr() == b.Addr() {
					intersection.Add(a)
				}
			} else if a.Prefix() < b.Prefix() {
				// See if a contains b.
				aNet := a.ToIPNet()
				if aNet.Contains(b.ToIPNet().IP) {
					// a contains b so intersection is b
					intersection.Add(b)
				}
			} else {
				// See if b contains a.
				bNet := b.ToIPNet()
				if bNet.Contains(a.ToIPNet().IP) {
					// b contains a so intersection is a
					intersection.Add(a)
				}
			}
		}
	}

	intersection.Iter(func(cidr ip.CIDR) error {
		out = append(out, cidr.String())
		return set.RemoveItem
	})

	// Sort the output for determinism both in testing and in rule generation.
	sort.Strings(out)

	return
}

func parseCIDRs(in []string) (out []ip.CIDR) {
	for _, s := range in {
		out = append(out, ip.MustParseCIDROrIP(s))
	}
	return
}
