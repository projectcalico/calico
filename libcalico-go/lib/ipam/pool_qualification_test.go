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

package ipam

import (
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

// Pool 1 of each family is written unnormalized (host bit set, full IPv6 form) so that naming it in a request
// exercises CIDR normalization.
const (
	qualV4Pool1 = "10.0.0.1/24"
	qualV4Pool2 = "20.0.0.0/24"
	qualV6Pool1 = "5001:0000:0000:001a:0000:0000:0000:0000/64"
	qualV6Pool2 = "5001:0:0:1b::/64"
)

// testPool holds the IP pool fields that pool qualification reads.
type testPool struct {
	cidr              string
	nodeSelector      string
	namespaceSelector string
	blockSize         int
	uses              []v3.IPPoolAllowedUse
	manual            bool
}

func (p testPool) build() v3.IPPool {
	mode := v3.Automatic
	if p.manual {
		mode = v3.Manual
	}
	uses := p.uses
	if uses == nil {
		uses = []v3.IPPoolAllowedUse{v3.IPPoolAllowedUseWorkload, v3.IPPoolAllowedUseTunnel}
	}
	blockSize := p.blockSize
	if blockSize == 0 {
		blockSize = 26
	}
	return v3.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: p.cidr},
		Spec: v3.IPPoolSpec{
			CIDR:              p.cidr,
			NodeSelector:      p.nodeSelector,
			NamespaceSelector: p.namespaceSelector,
			BlockSize:         blockSize,
			AllowedUses:       uses,
			AssignmentMode:    &mode,
		},
	}
}

func buildPools(pools []testPool) []v3.IPPool {
	var out []v3.IPPool
	for _, p := range pools {
		out = append(out, p.build())
	}
	return out
}

func collectCIDRs(pools []v3.IPPool) []string {
	cidrs := []string{}
	for _, p := range pools {
		cidrs = append(cidrs, p.Spec.CIDR)
	}
	return cidrs
}

func parseRequestedPools(cidrs ...string) []cnet.IPNet {
	var nets []cnet.IPNet
	for _, c := range cidrs {
		nets = append(nets, cnet.MustParseCIDR(c))
	}
	return nets
}

func testNamespace(labels map[string]string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns", Labels: labels}}
}

// qualificationCase is one row of the qualifyPools table.
type qualificationCase struct {
	pools        []testPool
	requested    []string
	nodeLabels   map[string]string
	namespace    *corev1.Namespace
	use          v3.IPPoolAllowedUse
	maxPrefixLen int

	// Either both pool lists or the error message is checked.
	qualified []string
	selecting []string
	err       string
}

var _ = DescribeTable("qualifyPools",
	func(tc qualificationCase) {
		use := tc.use
		if use == "" {
			use = v3.IPPoolAllowedUseWorkload
		}
		maxPrefixLen := tc.maxPrefixLen
		if maxPrefixLen == 0 {
			maxPrefixLen = 128
		}
		nodeLabels := tc.nodeLabels
		if nodeLabels == nil {
			nodeLabels = map[string]string{"foo": "bar"}
		}
		req := poolRequest{
			requested:    parseRequestedPools(tc.requested...),
			host:         "host1",
			node:         internalapi.Node{ObjectMeta: metav1.ObjectMeta{Labels: nodeLabels}},
			namespace:    tc.namespace,
			use:          use,
			maxPrefixLen: maxPrefixLen,
		}

		q, err := qualifyPools(req, buildPools(tc.pools))

		if tc.err != "" {
			Expect(err).To(MatchError(tc.err))
			return
		}
		Expect(err).NotTo(HaveOccurred())
		Expect(collectCIDRs(q.qualified())).To(Equal(tc.qualified))
		Expect(collectCIDRs(q.selecting())).To(Equal(tc.selecting))
	},

	// Node selectors, with and without named pools. A disabled pool is one GetEnabledPools leaves out.
	Entry("no selectors, nothing named", qualificationCase{
		pools:     []testPool{{cidr: qualV4Pool1}, {cidr: qualV4Pool2}},
		qualified: []string{qualV4Pool1, qualV4Pool2},
		selecting: []string{qualV4Pool1, qualV4Pool2},
	}),
	Entry("no selectors, pool1 named", qualificationCase{
		pools:     []testPool{{cidr: qualV4Pool1}, {cidr: qualV4Pool2}},
		requested: []string{qualV4Pool1},
		qualified: []string{qualV4Pool1},
		selecting: []string{qualV4Pool1},
	}),
	Entry("only pool1 selects the node", qualificationCase{
		pools:     []testPool{{cidr: qualV4Pool1, nodeSelector: `foo == "bar"`}, {cidr: qualV4Pool2, nodeSelector: `foo != "bar"`}},
		qualified: []string{qualV4Pool1},
		selecting: []string{qualV4Pool1},
	}),
	Entry("pool1 doesn't select the node, pool2 selects all()", qualificationCase{
		pools:     []testPool{{cidr: qualV4Pool1, nodeSelector: `foo != "bar"`}, {cidr: qualV4Pool2, nodeSelector: "all()"}},
		qualified: []string{qualV4Pool2},
		selecting: []string{qualV4Pool2},
	}),
	Entry("pool2 named although pool1 selects the node", qualificationCase{
		pools:     []testPool{{cidr: qualV4Pool1, nodeSelector: `foo == "bar"`}, {cidr: qualV4Pool2}},
		requested: []string{qualV4Pool2},
		qualified: []string{qualV4Pool2},
		selecting: []string{qualV4Pool2},
	}),
	Entry("pool1 disabled, nothing named", qualificationCase{
		pools:     []testPool{{cidr: qualV4Pool2}},
		qualified: []string{qualV4Pool2},
		selecting: []string{qualV4Pool2},
	}),
	Entry("pool1 disabled and named", qualificationCase{
		pools:     []testPool{{cidr: qualV4Pool2}},
		requested: []string{qualV4Pool1},
		err:       "the given pool (10.0.0.0/24) does not exist, or is not enabled",
	}),
	Entry("a disabled pool named alongside an enabled one", qualificationCase{
		pools:     []testPool{{cidr: qualV4Pool2}},
		requested: []string{qualV4Pool2, qualV4Pool1},
		err:       "the given pool (10.0.0.0/24) does not exist, or is not enabled",
	}),
	Entry("pool1 disabled, pool2 named", qualificationCase{
		pools:     []testPool{{cidr: qualV4Pool2}},
		requested: []string{qualV4Pool2},
		qualified: []string{qualV4Pool2},
		selecting: []string{qualV4Pool2},
	}),
	Entry("the only enabled pool doesn't select the node", qualificationCase{
		pools: []testPool{{cidr: qualV4Pool2, nodeSelector: `foo != "bar"`}},
		err:   "no configured Calico pools for node host1",
	}),
	Entry("IPv6 pools, nothing named", qualificationCase{
		pools:     []testPool{{cidr: qualV6Pool1}, {cidr: qualV6Pool2}},
		qualified: []string{qualV6Pool1, qualV6Pool2},
		selecting: []string{qualV6Pool1, qualV6Pool2},
	}),
	Entry("IPv6 pool named in full representation", qualificationCase{
		pools:     []testPool{{cidr: qualV6Pool1, nodeSelector: `foo == "bar"`}, {cidr: qualV6Pool2, nodeSelector: `foo != "bar"`}},
		requested: []string{qualV6Pool1},
		qualified: []string{qualV6Pool1},
		selecting: []string{qualV6Pool1},
	}),

	// Namespace selectors.
	Entry("namespace selector matches", qualificationCase{
		pools:     []testPool{{cidr: qualV4Pool2, namespaceSelector: "environment == 'production'"}},
		namespace: testNamespace(map[string]string{"environment": "production"}),
		qualified: []string{qualV4Pool2},
		selecting: []string{qualV4Pool2},
	}),
	Entry("namespace selector doesn't match", qualificationCase{
		pools:     []testPool{{cidr: qualV4Pool2, namespaceSelector: "environment == 'production'"}},
		namespace: testNamespace(map[string]string{"environment": "development"}),
		err:       "no configured Calico pools for node host1",
	}),
	Entry("namespace selector against no namespace", qualificationCase{
		pools: []testPool{{cidr: qualV4Pool2, namespaceSelector: "environment == 'production'"}},
		err:   "no configured Calico pools for node host1",
	}),
	Entry("node selector matches but namespace selector doesn't", qualificationCase{
		pools:      []testPool{{cidr: qualV4Pool2, nodeSelector: "zone == 'us-west'", namespaceSelector: "environment == 'production'"}},
		nodeLabels: map[string]string{"zone": "us-west"},
		namespace:  testNamespace(map[string]string{"environment": "development"}),
		err:        "no configured Calico pools for node host1",
	}),
	Entry("compound namespace selector", qualificationCase{
		pools: []testPool{
			{cidr: "10.0.0.0/24", namespaceSelector: "environment == 'production' && tier == 'frontend'"},
			{cidr: "10.1.0.0/24", namespaceSelector: "environment == 'production' && tier == 'backend'"},
		},
		namespace: testNamespace(map[string]string{
			"environment": "production",
			"tier":        "frontend",
		}),
		qualified: []string{"10.0.0.0/24"},
		selecting: []string{"10.0.0.0/24"},
	}),
	Entry("several pools with different namespace selectors", qualificationCase{
		pools: []testPool{
			{cidr: "10.0.0.0/24", namespaceSelector: "environment == 'production'"},
			{cidr: "10.1.0.0/24", namespaceSelector: "environment == 'development'"},
			{cidr: "10.2.0.0/24"},
		},
		namespace: testNamespace(map[string]string{"environment": "production"}),
		qualified: []string{"10.0.0.0/24", "10.2.0.0/24"},
		selecting: []string{"10.0.0.0/24", "10.2.0.0/24"},
	}),

	// Named pools skip the node selector, namespace selector and AssignmentMode, and nothing else.
	Entry("named pool skips a mismatched node selector", qualificationCase{
		pools:     []testPool{{cidr: qualV4Pool1, nodeSelector: `foo != "bar"`}},
		requested: []string{qualV4Pool1},
		qualified: []string{qualV4Pool1},
		selecting: []string{qualV4Pool1},
	}),
	Entry("named pool skips a mismatched namespace selector", qualificationCase{
		pools:     []testPool{{cidr: "10.0.0.0/24", namespaceSelector: "environment == 'production'"}},
		requested: []string{"10.0.0.0/24"},
		namespace: testNamespace(map[string]string{"environment": "development"}),
		qualified: []string{"10.0.0.0/24"},
		selecting: []string{"10.0.0.0/24"},
	}),
	Entry("named pool skips Manual assignment mode", qualificationCase{
		pools:     []testPool{{cidr: qualV4Pool1, manual: true}},
		requested: []string{qualV4Pool1},
		qualified: []string{qualV4Pool1},
		selecting: []string{qualV4Pool1},
	}),
	Entry("named pool still needs a matching use", qualificationCase{
		pools:     []testPool{{cidr: qualV4Pool1}},
		requested: []string{qualV4Pool1},
		use:       v3.IPPoolAllowedUseLoadBalancer,
		err:       "cannot find a qualified ippool, no pools match the required use (LoadBalancer)",
	}),
	Entry("named pool still needs a block size within maxPrefixLen", qualificationCase{
		pools:        []testPool{{cidr: qualV4Pool1, blockSize: 31}, {cidr: qualV4Pool2}},
		requested:    []string{qualV4Pool1},
		maxPrefixLen: 29,
		err:          "the given pool (10.0.0.0/24) does not exist, or is not enabled",
	}),
	Entry("named pools keep the order they were named in", qualificationCase{
		pools:     []testPool{{cidr: qualV4Pool1}, {cidr: qualV4Pool2}},
		requested: []string{qualV4Pool2, qualV4Pool1},
		qualified: []string{qualV4Pool2, qualV4Pool1},
		selecting: []string{qualV4Pool2, qualV4Pool1},
	}),

	// Rules that only automatic selection applies.
	Entry("Manual pool is skipped when nothing is named", qualificationCase{
		pools:     []testPool{{cidr: qualV4Pool1, manual: true}, {cidr: qualV4Pool2}},
		qualified: []string{qualV4Pool2},
		selecting: []string{qualV4Pool2},
	}),
	Entry("automatic selection doesn't check each pool's block size", qualificationCase{
		pools:        []testPool{{cidr: qualV4Pool1, blockSize: 31}, {cidr: qualV4Pool2}},
		maxPrefixLen: 29,
		qualified:    []string{qualV4Pool1, qualV4Pool2},
		selecting:    []string{qualV4Pool1, qualV4Pool2},
	}),

	// Allowed use separates qualified pools from pools that only select the node.
	Entry("pool rejected for use still selects the node", qualificationCase{
		pools:     []testPool{{cidr: qualV4Pool1, uses: []v3.IPPoolAllowedUse{v3.IPPoolAllowedUseTunnel}}, {cidr: qualV4Pool2}},
		qualified: []string{qualV4Pool2},
		selecting: []string{qualV4Pool1, qualV4Pool2},
	}),
	Entry("no pool allows the use", qualificationCase{
		pools: []testPool{{cidr: qualV4Pool1}, {cidr: qualV4Pool2}},
		use:   v3.IPPoolAllowedUseLoadBalancer,
		err:   "cannot find a qualified ippool, no pools match the required use (LoadBalancer)",
	}),
)

var _ = Describe("qualifyPools errors", func() {
	node := internalapi.Node{}

	It("returns ErrNoQualifiedPool when no pool's block size fits", func() {
		_, err := qualifyPools(poolRequest{node: node, use: v3.IPPoolAllowedUseWorkload, maxPrefixLen: 29}, buildPools([]testPool{{cidr: qualV4Pool1, blockSize: 31}}))
		Expect(err).To(Equal(ErrNoQualifiedPool))
	})

	It("wraps ErrNoQualifiedPool when no pool allows the use", func() {
		_, err := qualifyPools(poolRequest{node: node, use: v3.IPPoolAllowedUseLoadBalancer, maxPrefixLen: 32}, buildPools([]testPool{{cidr: qualV4Pool1}}))
		Expect(err).To(MatchError(ErrNoQualifiedPool))
	})

	It("returns the error from an unparseable node selector", func() {
		_, err := qualifyPools(
			poolRequest{node: node, use: v3.IPPoolAllowedUseWorkload, maxPrefixLen: 32},
			buildPools([]testPool{{cidr: qualV4Pool1, nodeSelector: "invalid selector syntax ["}}),
		)
		Expect(err).To(HaveOccurred())
	})

	It("returns the error from an unparseable namespace selector", func() {
		_, err := qualifyPools(
			poolRequest{node: node, use: v3.IPPoolAllowedUseWorkload, maxPrefixLen: 32, namespace: testNamespace(nil)},
			buildPools([]testPool{{cidr: qualV4Pool1, namespaceSelector: "invalid selector syntax ["}}),
		)
		Expect(err).To(HaveOccurred())
	})
})

var _ = DescribeTable("qualifyPoolForIP",
	func(use v3.IPPoolAllowedUse, expectedErr string) {
		pool := testPool{cidr: "10.0.0.0/24", uses: []v3.IPPoolAllowedUse{v3.IPPoolAllowedUseWorkload}}.build()
		err := qualifyPoolForIP(cnet.IP{IP: net.ParseIP("10.0.0.1")}, pool, use)
		if expectedErr == "" {
			Expect(err).NotTo(HaveOccurred())
		} else {
			Expect(err).To(MatchError(expectedErr))
		}
	},
	Entry("use is allowed", v3.IPPoolAllowedUseWorkload, ""),
	Entry("no use declared", v3.IPPoolAllowedUse(""), ""),
	Entry("use isn't allowed", v3.IPPoolAllowedUseTunnel, `IP address 10.0.0.1 is in IP pool "10.0.0.0/24", which is not allowed for use "Tunnel" (allowedUses: [Workload])`),
)
