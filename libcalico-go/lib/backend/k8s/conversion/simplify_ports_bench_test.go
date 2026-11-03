// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package conversion

import (
	"fmt"
	"math/rand/v2"
	"testing"

	"github.com/projectcalico/api/pkg/lib/numorstring"
)

type simplifyPortsBenchCase struct {
	name  string
	ports []numorstring.Port
}

// simplifyPortsBenchCases sizes inputs near the NetworkPolicy worst case:
// rules have no MaxItems on ports, so request size (~1.5MiB) is the only
// limit, which allows ~10^5 entries.
func simplifyPortsBenchCases(sizes ...int) []simplifyPortsBenchCase {
	var cases []simplifyPortsBenchCase
	for _, n := range sizes {
		rng := rand.New(rand.NewPCG(1, uint64(n)))
		randomPort := func() uint16 { return uint16(1 + rng.IntN(65535)) }

		singles := make([]numorstring.Port, n)
		narrow := make([]numorstring.Port, n)
		full := make([]numorstring.Port, n)
		for i := range n {
			singles[i] = numorstring.SinglePort(randomPort())
			lo := randomPort()
			narrow[i] = numorstring.Port{MinPort: lo, MaxPort: lo + uint16(min(rng.IntN(64), 65535-int(lo)))}
			full[i] = numorstring.Port{MinPort: 1, MaxPort: 65535}
		}
		cases = append(cases,
			simplifyPortsBenchCase{fmt.Sprintf("singles/n=%d", n), singles},
			simplifyPortsBenchCase{fmt.Sprintf("narrow-ranges/n=%d", n), narrow},
			simplifyPortsBenchCase{fmt.Sprintf("full-ranges/n=%d", n), full},
		)
	}
	return cases
}

func BenchmarkSimplifyPorts(b *testing.B) {
	for _, c := range simplifyPortsBenchCases(5, 25, 1000, 100_000) {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				SimplifyPorts(c.ports)
			}
		})
	}
}
