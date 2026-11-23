// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package checker

import (
	"fmt"
	"testing"

	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/felix/types"
)

// With debug logging off, walking a tier costs the same allocations however many policies it
// holds, including staged policies skipped when enforcing: nothing logged per policy may build
// its arguments.
func TestEvaluateAllocationsDoNotGrowWithPolicies(t *testing.T) {
	RegisterTestingT(t)
	oldLevel := logrus.GetLevel()
	logrus.SetLevel(logrus.InfoLevel)
	t.Cleanup(func() { logrus.SetLevel(oldLevel) })

	allocsFor := func(policies int) float64 {
		store := policystore.NewPolicyStore()
		var ids []*proto.PolicyID
		for i := range policies {
			kind := v3.KindGlobalNetworkPolicy
			if i%2 == 1 {
				kind = v3.KindStagedGlobalNetworkPolicy
			}
			id := &proto.PolicyID{Name: fmt.Sprintf("policy-%d", i), Kind: kind}
			ids = append(ids, id)
			store.PolicyByID[types.ProtoToPolicyID(id)] = &proto.Policy{}
		}
		ep := &proto.WorkloadEndpoint{Tiers: tierInfos(ids)}
		flow := &MockFlow{Protocol: 6, DestPort: 80}
		return testing.AllocsPerRun(20, func() {
			_, _ = Evaluate(EnforcedOnly, rules.RuleDirIngress, store, ep, flow)
		})
	}
	// Ordinals up to 255 box without allocating, so compare two tiers longer than that. A logged
	// ordinal would add one allocation per policy; the race detector adds a few stray ones.
	Expect(allocsFor(1200)).To(BeNumerically("<", allocsFor(600)+10))
}

// A request path that can't be normalized fails every rule with HTTP paths that the walk reaches,
// so with debug logging off the check must cost no more than the normalization itself.
func TestUnnormalizablePathCheckDoesNotAllocate(t *testing.T) {
	RegisterTestingT(t)
	oldLevel := logrus.GetLevel()
	logrus.SetLevel(logrus.InfoLevel)
	t.Cleanup(func() { logrus.SetLevel(oldLevel) })

	paths := []*proto.HTTPMatch_PathMatch{{PathMatch: &proto.HTTPMatch_PathMatch_Prefix{Prefix: "/public"}}}
	reqPath := "/admin%00/../public"
	_, ok := normalizeHTTPPath(reqPath)
	Expect(ok).To(BeFalse())
	Expect(matchHTTPPaths(paths, &reqPath)).To(BeFalse())

	normalizeAllocs := testing.AllocsPerRun(100, func() { normalizeHTTPPath(reqPath) })
	matchAllocs := testing.AllocsPerRun(100, func() { matchHTTPPaths(paths, &reqPath) })
	// Building a log entry costs several allocations; the race detector adds a stray one at times.
	Expect(matchAllocs).To(BeNumerically("<=", normalizeAllocs+2))
}
