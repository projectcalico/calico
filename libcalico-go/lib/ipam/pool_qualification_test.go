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
	"errors"

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
	v4Pool1 = "10.0.0.1/24"
	v4Pool2 = "20.0.0.0/24"
	v6Pool1 = "5001:0000:0000:001a:0000:0000:0000:0000/64"
	v6Pool2 = "5001:0:0:1b::/64"
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

// build returns the IP pool, defaulting to Automatic assignment, block size 26, and workload and tunnel uses.
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

// releasedPools returns the CIDRs of the pools whose empty affine blocks the qualification releases, asking keepsBlock
// about one block at the start of each pool.
func releasedPools(q poolQualification, pools []v3.IPPool) []string {
	released := []string{}
	for _, p := range pools {
		kept, err := q.keepsBlock(cnet.MustParseNetwork(p.Spec.CIDR))
		ExpectWithOffset(1, err).NotTo(HaveOccurred())
		if !kept {
			released = append(released, p.Spec.CIDR)
		}
	}
	return released
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

	// Either both pool lists or the error message is checked. released lists the pools whose empty affine blocks are
	// released, unordered, and is empty when left out.
	qualified []string
	released  []string
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

		pools := buildPools(tc.pools)
		q, err := qualifyPools(req, pools)

		if tc.err != "" {
			Expect(err).To(MatchError(tc.err))
			return
		}
		Expect(err).NotTo(HaveOccurred())
		Expect(collectCIDRs(q.qualified())).To(Equal(tc.qualified))
		Expect(releasedPools(q, pools)).To(ConsistOf(tc.released))
	},

	// Node selectors, with and without named pools. A disabled pool is one GetEnabledPools leaves out.
	Entry("no selectors, nothing named", qualificationCase{
		pools:     []testPool{{cidr: v4Pool1}, {cidr: v4Pool2}},
		qualified: []string{v4Pool1, v4Pool2},
	}),
	Entry("no selectors, pool1 named", qualificationCase{
		pools:     []testPool{{cidr: v4Pool1}, {cidr: v4Pool2}},
		requested: []string{v4Pool1},
		qualified: []string{v4Pool1},
	}),
	Entry("only pool1 selects the node", qualificationCase{
		pools:     []testPool{{cidr: v4Pool1, nodeSelector: `foo == "bar"`}, {cidr: v4Pool2, nodeSelector: `foo != "bar"`}},
		qualified: []string{v4Pool1},
		released:  []string{v4Pool2},
	}),
	Entry("pool1 doesn't select the node, pool2 selects all()", qualificationCase{
		pools:     []testPool{{cidr: v4Pool1, nodeSelector: `foo != "bar"`}, {cidr: v4Pool2, nodeSelector: "all()"}},
		qualified: []string{v4Pool2},
		released:  []string{v4Pool1},
	}),
	Entry("pool2 named although pool1 selects the node", qualificationCase{
		pools:     []testPool{{cidr: v4Pool1, nodeSelector: `foo == "bar"`}, {cidr: v4Pool2}},
		requested: []string{v4Pool2},
		qualified: []string{v4Pool2},
	}),
	Entry("pool1 disabled, nothing named", qualificationCase{
		pools:     []testPool{{cidr: v4Pool2}},
		qualified: []string{v4Pool2},
	}),
	Entry("pool1 disabled and named", qualificationCase{
		pools:     []testPool{{cidr: v4Pool2}},
		requested: []string{v4Pool1},
		err:       "the given pool (10.0.0.0/24) does not exist, or is not enabled",
	}),
	Entry("a disabled pool named alongside an enabled one", qualificationCase{
		pools:     []testPool{{cidr: v4Pool2}},
		requested: []string{v4Pool2, v4Pool1},
		err:       "the given pool (10.0.0.0/24) does not exist, or is not enabled",
	}),
	Entry("pool1 disabled, pool2 named", qualificationCase{
		pools:     []testPool{{cidr: v4Pool2}},
		requested: []string{v4Pool2},
		qualified: []string{v4Pool2},
	}),
	Entry("the only enabled pool doesn't select the node", qualificationCase{
		pools: []testPool{{cidr: v4Pool2, nodeSelector: `foo != "bar"`}},
		err:   "no configured Calico pools for node host1",
	}),
	Entry("IPv6 pools, nothing named", qualificationCase{
		pools:     []testPool{{cidr: v6Pool1}, {cidr: v6Pool2}},
		qualified: []string{v6Pool1, v6Pool2},
	}),
	Entry("IPv6 pool named in full representation", qualificationCase{
		pools:     []testPool{{cidr: v6Pool1, nodeSelector: `foo == "bar"`}, {cidr: v6Pool2, nodeSelector: `foo != "bar"`}},
		requested: []string{v6Pool1},
		qualified: []string{v6Pool1},
		released:  []string{v6Pool2},
	}),

	// Namespace selectors.
	Entry("namespace selector matches", qualificationCase{
		pools:     []testPool{{cidr: v4Pool2, namespaceSelector: "environment == 'production'"}},
		namespace: testNamespace(map[string]string{"environment": "production"}),
		qualified: []string{v4Pool2},
	}),
	Entry("namespace selector doesn't match", qualificationCase{
		pools:     []testPool{{cidr: v4Pool2, namespaceSelector: "environment == 'production'"}},
		namespace: testNamespace(map[string]string{"environment": "development"}),
		err:       "no configured Calico pools for node host1",
	}),
	Entry("namespace selector against no namespace", qualificationCase{
		pools: []testPool{{cidr: v4Pool2, namespaceSelector: "environment == 'production'"}},
		err:   "no configured Calico pools for node host1",
	}),
	Entry("node selector matches but namespace selector doesn't", qualificationCase{
		pools:      []testPool{{cidr: v4Pool2, nodeSelector: "zone == 'us-west'", namespaceSelector: "environment == 'production'"}},
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
	}),
	Entry("several pools with different namespace selectors", qualificationCase{
		pools: []testPool{
			{cidr: "10.0.0.0/24", namespaceSelector: "environment == 'production'"},
			{cidr: "10.1.0.0/24", namespaceSelector: "environment == 'development'"},
			{cidr: "10.2.0.0/24"},
		},
		namespace: testNamespace(map[string]string{"environment": "production"}),
		qualified: []string{"10.0.0.0/24", "10.2.0.0/24"},
	}),

	// Named pools skip the node selector, namespace selector and AssignmentMode, and nothing else.
	Entry("named pool skips a mismatched node selector", qualificationCase{
		pools:     []testPool{{cidr: v4Pool1, nodeSelector: `foo != "bar"`}},
		requested: []string{v4Pool1},
		qualified: []string{v4Pool1},
	}),
	Entry("named pool skips a mismatched namespace selector", qualificationCase{
		pools:     []testPool{{cidr: "10.0.0.0/24", namespaceSelector: "environment == 'production'"}},
		requested: []string{"10.0.0.0/24"},
		namespace: testNamespace(map[string]string{"environment": "development"}),
		qualified: []string{"10.0.0.0/24"},
	}),
	Entry("named pool skips Manual assignment mode", qualificationCase{
		pools:     []testPool{{cidr: v4Pool1, manual: true}},
		requested: []string{v4Pool1},
		qualified: []string{v4Pool1},
	}),
	Entry("named pool still needs a matching use", qualificationCase{
		pools:     []testPool{{cidr: v4Pool1}},
		requested: []string{v4Pool1},
		use:       v3.IPPoolAllowedUseLoadBalancer,
		err:       "cannot find a qualified ippool, no pools match the required use (LoadBalancer)",
	}),
	Entry("named pool still needs a block size within maxPrefixLen", qualificationCase{
		pools:        []testPool{{cidr: v4Pool1, blockSize: 31}, {cidr: v4Pool2}},
		requested:    []string{v4Pool1},
		maxPrefixLen: 29,
		err:          "the given pool (10.0.0.0/24) does not exist, or is not enabled",
	}),
	Entry("named pools keep the order they were named in", qualificationCase{
		pools:     []testPool{{cidr: v4Pool1}, {cidr: v4Pool2}},
		requested: []string{v4Pool2, v4Pool1},
		qualified: []string{v4Pool2, v4Pool1},
	}),

	// Rules that only automatic selection applies.
	Entry("Manual pool is skipped when nothing is named", qualificationCase{
		pools:     []testPool{{cidr: v4Pool1, manual: true}, {cidr: v4Pool2}},
		qualified: []string{v4Pool2},
	}),
	Entry("automatic selection doesn't check each pool's block size", qualificationCase{
		pools:        []testPool{{cidr: v4Pool1, blockSize: 31}, {cidr: v4Pool2}},
		maxPrefixLen: 29,
		qualified:    []string{v4Pool1, v4Pool2},
	}),

	// Allowed use separates qualified pools from pools that only select the node.
	Entry("pool rejected for use still selects the node", qualificationCase{
		pools:     []testPool{{cidr: v4Pool1, uses: []v3.IPPoolAllowedUse{v3.IPPoolAllowedUseTunnel}}, {cidr: v4Pool2}},
		qualified: []string{v4Pool2},
	}),

	// Release follows the node selector alone, whatever else rejected the pool, and never touches a named pool.
	Entry("a Manual pool whose node selector skips the node releases its blocks", qualificationCase{
		pools:     []testPool{{cidr: v4Pool1, manual: true, nodeSelector: `foo != "bar"`}, {cidr: v4Pool2}},
		qualified: []string{v4Pool2},
		released:  []string{v4Pool1},
	}),
	Entry("a pool rejected only by its namespace selector keeps its blocks", qualificationCase{
		pools: []testPool{
			{cidr: v4Pool1, namespaceSelector: "environment == 'production'"},
			{cidr: v4Pool2},
		},
		namespace: testNamespace(map[string]string{"environment": "development"}),
		qualified: []string{v4Pool2},
	}),
	Entry("an unnamed pool that skips the node releases its blocks, a named one does not", qualificationCase{
		pools:     []testPool{{cidr: v4Pool1, nodeSelector: `foo != "bar"`}, {cidr: v4Pool2, nodeSelector: `foo != "bar"`}},
		requested: []string{v4Pool1},
		qualified: []string{v4Pool1},
		released:  []string{v4Pool2},
	}),
	Entry("a pool whose node selector doesn't parse keeps its blocks", qualificationCase{
		pools:     []testPool{{cidr: v4Pool1, manual: true, nodeSelector: "invalid selector syntax ["}, {cidr: v4Pool2}},
		qualified: []string{v4Pool2},
	}),
	Entry("no pool allows the use", qualificationCase{
		pools: []testPool{{cidr: v4Pool1}, {cidr: v4Pool2}},
		use:   v3.IPPoolAllowedUseLoadBalancer,
		err:   "cannot find a qualified ippool, no pools match the required use (LoadBalancer)",
	}),
)

var _ = Describe("qualifyPools errors", func() {
	It("returns ErrNoQualifiedPool when no pool's block size fits", func() {
		_, err := qualifyPools(poolRequest{use: v3.IPPoolAllowedUseWorkload, maxPrefixLen: 29}, buildPools([]testPool{{cidr: v4Pool1, blockSize: 31}}))
		Expect(err).To(Equal(ErrNoQualifiedPool))
	})

	It("wraps ErrNoQualifiedPool when no pool allows the use", func() {
		_, err := qualifyPools(poolRequest{use: v3.IPPoolAllowedUseLoadBalancer, maxPrefixLen: 32}, buildPools([]testPool{{cidr: v4Pool1}}))
		Expect(err).To(MatchError(ErrNoQualifiedPool))
	})

	It("returns the error from an unparseable node selector", func() {
		_, err := qualifyPools(poolRequest{use: v3.IPPoolAllowedUseWorkload, maxPrefixLen: 32}, buildPools([]testPool{{cidr: v4Pool1, nodeSelector: "invalid selector syntax ["}}))
		Expect(err).To(HaveOccurred())
	})

	It("returns the error from an unparseable namespace selector", func() {
		_, err := qualifyPools(
			poolRequest{use: v3.IPPoolAllowedUseWorkload, maxPrefixLen: 32, namespace: testNamespace(nil)},
			buildPools([]testPool{{cidr: v4Pool1, namespaceSelector: "invalid selector syntax ["}}),
		)
		Expect(err).To(HaveOccurred())
	})
})

var _ = DescribeTable("qualifyPoolForIP",
	func(use v3.IPPoolAllowedUse, expectedErr string) {
		pool := testPool{cidr: "10.0.0.0/24", uses: []v3.IPPoolAllowedUse{v3.IPPoolAllowedUseWorkload}}.build()
		err := qualifyPoolForIP(cnet.MustParseIP("10.0.0.1"), pool, use)
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

// undefaultedPool returns a pool as a caller might build it before clientv3 defaults it, with no assignment mode
// and no allowed uses.
func undefaultedPool(cidr string) v3.IPPool {
	pool := testPool{cidr: cidr}.build()
	pool.Spec.AssignmentMode = nil
	pool.Spec.AllowedUses = nil
	return pool
}

var _ = Describe("pool qualification of undefaulted pools", func() {
	It("treats a missing assignment mode as Automatic", func() {
		q, err := qualifyPools(poolRequest{use: v3.IPPoolAllowedUseWorkload, maxPrefixLen: 32}, []v3.IPPool{undefaultedPool(v4Pool1)})
		Expect(err).NotTo(HaveOccurred())
		Expect(collectCIDRs(q.qualified())).To(Equal([]string{v4Pool1}))
	})

	It("allows tunnel use when allowed uses are empty", func() {
		q, err := qualifyPools(poolRequest{use: v3.IPPoolAllowedUseTunnel, maxPrefixLen: 32}, []v3.IPPool{undefaultedPool(v4Pool1)})
		Expect(err).NotTo(HaveOccurred())
		Expect(collectCIDRs(q.qualified())).To(Equal([]string{v4Pool1}))
	})

	It("still rejects LoadBalancer use when allowed uses are empty", func() {
		_, err := qualifyPools(poolRequest{use: v3.IPPoolAllowedUseLoadBalancer, maxPrefixLen: 32}, []v3.IPPool{undefaultedPool(v4Pool1)})
		Expect(err).To(MatchError(ErrNoQualifiedPool))
	})

	It("allows a specific IP for workload use when allowed uses are empty", func() {
		Expect(qualifyPoolForIP(cnet.MustParseIP("10.0.0.1"), undefaultedPool("10.0.0.0/24"), v3.IPPoolAllowedUseWorkload)).To(Succeed())
	})

	It("rejects a specific IP for LoadBalancer use when allowed uses are empty", func() {
		Expect(qualifyPoolForIP(cnet.MustParseIP("10.0.0.1"), undefaultedPool("10.0.0.0/24"), v3.IPPoolAllowedUseLoadBalancer)).NotTo(Succeed())
	})
})

// releaseCase is one row of the blocksToRelease table. Every row adds a pool the request can use, so qualification
// succeeds, and asks about the node's affine blocks in the other pools.
type releaseCase struct {
	pools    []testPool
	blocks   []string
	released []string
}

var _ = DescribeTable("blocksToRelease",
	func(tc releaseCase) {
		pools := append([]testPool{{cidr: "20.0.0.0/24"}}, tc.pools...)
		req := poolRequest{
			node:         internalapi.Node{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"foo": "bar"}}},
			use:          v3.IPPoolAllowedUseWorkload,
			maxPrefixLen: 32,
		}
		q, err := qualifyPools(req, buildPools(pools))
		Expect(err).NotTo(HaveOccurred())

		var blocks []cnet.IPNet
		for _, b := range tc.blocks {
			blocks = append(blocks, cnet.MustParseNetwork(b))
		}
		released, err := q.blocksToRelease(blocks)
		Expect(err).NotTo(HaveOccurred())

		got := []string{}
		for _, b := range released {
			got = append(got, b.String())
		}
		Expect(got).To(ConsistOf(tc.released))
	},
	Entry("a block in a pool that skips the node is released", releaseCase{
		pools:    []testPool{{cidr: "30.0.0.0/24", nodeSelector: `foo != "bar"`}},
		blocks:   []string{"30.0.0.0/26"},
		released: []string{"30.0.0.0/26"},
	}),
	Entry("a block in a pool that selects the node but disallows the use is kept", releaseCase{
		pools:  []testPool{{cidr: "10.0.0.0/16", uses: []v3.IPPoolAllowedUse{v3.IPPoolAllowedUseTunnel}}},
		blocks: []string{"10.0.0.0/26"},
	}),
	Entry("a block also covered by an overlapping pool that skips the node is kept", releaseCase{
		pools: []testPool{
			{cidr: "10.0.0.0/16", uses: []v3.IPPoolAllowedUse{v3.IPPoolAllowedUseTunnel}},
			{cidr: "10.0.0.0/24", nodeSelector: `foo != "bar"`},
		},
		blocks: []string{"10.0.0.0/26"},
	}),
	Entry("the overlap keeps the block whichever pool comes first", releaseCase{
		pools: []testPool{
			{cidr: "10.0.0.0/24", nodeSelector: `foo != "bar"`},
			{cidr: "10.0.0.0/16", uses: []v3.IPPoolAllowedUse{v3.IPPoolAllowedUseTunnel}},
		},
		blocks: []string{"10.0.0.0/26"},
	}),
	Entry("a Manual pool that selects the node keeps its block", releaseCase{
		pools:  []testPool{{cidr: "30.0.0.0/24", manual: true}},
		blocks: []string{"30.0.0.0/26"},
	}),
	Entry("a pool rejected only by its namespace selector keeps its block", releaseCase{
		pools:  []testPool{{cidr: "30.0.0.0/24", namespaceSelector: "environment == 'production'"}},
		blocks: []string{"30.0.0.0/26"},
	}),
)

var _ = Describe("qualifyPools with unnamed pools", func() {
	It("matches named pools by CIDR, so an unrequested pool that skips the node still releases its blocks", func() {
		pools := buildPools([]testPool{{cidr: v4Pool1, nodeSelector: `foo != "bar"`}, {cidr: v4Pool2}})
		for i := range pools {
			pools[i].Name = ""
		}
		req := poolRequest{
			requested:    parseRequestedPools(v4Pool2),
			node:         internalapi.Node{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"foo": "bar"}}},
			use:          v3.IPPoolAllowedUseWorkload,
			maxPrefixLen: 32,
		}
		q, err := qualifyPools(req, pools)
		Expect(err).NotTo(HaveOccurred())
		Expect(collectCIDRs(q.qualified())).To(Equal([]string{v4Pool2}))
		Expect(releasedPools(q, pools)).To(Equal([]string{v4Pool1}))
	})
})

var errSelectorsConsulted = errors.New("selectors consulted")

// fixedSelectors answers the selector checks with fixed results. When untouchable, it fails any check, so a case can
// show that MayUse decided without the selectors.
type fixedSelectors struct {
	node        bool
	namespace   bool
	untouchable bool
}

func (s fixedSelectors) SelectsNode(*v3.IPPool) (bool, error) {
	if s.untouchable {
		return false, errSelectorsConsulted
	}
	return s.node, nil
}

func (s fixedSelectors) SelectsNamespace(*v3.IPPool) (bool, error) {
	if s.untouchable {
		return false, errSelectorsConsulted
	}
	return s.namespace, nil
}

// mayUseCase is one row of the PoolClaim.MayUse table. The claim asks for Workload use and names pools by CIDR.
type mayUseCase struct {
	pool      testPool
	pools     []string
	selectors fixedSelectors
	want      bool
}

var _ = DescribeTable("PoolClaim.MayUse",
	func(tc mayUseCase) {
		pool := tc.pool.build()
		claim := NewPoolClaim(v3.IPPoolAllowedUseWorkload, parseRequestedPools(tc.pools...), tc.selectors)
		Expect(claim.MayUse(&pool)).To(Equal(tc.want))
	},
	Entry("an Automatic pool whose selectors match", mayUseCase{
		pool:      testPool{cidr: v4Pool1},
		selectors: fixedSelectors{node: true, namespace: true},
		want:      true,
	}),
	Entry("not a Manual pool, for a claim naming no pool, without consulting its selectors", mayUseCase{
		pool:      testPool{cidr: v4Pool1, manual: true},
		selectors: fixedSelectors{untouchable: true},
	}),
	Entry("a Manual pool the claim names", mayUseCase{
		pool:      testPool{cidr: v4Pool1, manual: true},
		pools:     []string{v4Pool1},
		selectors: fixedSelectors{untouchable: true},
		want:      true,
	}),
	Entry("a pool the claim names by another form of its CIDR", mayUseCase{
		pool:      testPool{cidr: v4Pool1},
		pools:     []string{"10.0.0.0/24"},
		selectors: fixedSelectors{untouchable: true},
		want:      true,
	}),
	Entry("not a pool the claim doesn't name, without consulting its selectors", mayUseCase{
		pool:      testPool{cidr: v4Pool1},
		pools:     []string{v4Pool2},
		selectors: fixedSelectors{untouchable: true},
	}),
	Entry("not a pool whose node selector skips the node", mayUseCase{
		pool:      testPool{cidr: v4Pool1},
		selectors: fixedSelectors{namespace: true},
	}),
	Entry("a pool whose selectors skip the node and namespace, when the claim names it", mayUseCase{
		pool:      testPool{cidr: v4Pool1},
		pools:     []string{v4Pool1},
		selectors: fixedSelectors{untouchable: true},
		want:      true,
	}),
	Entry("not a pool whose namespace selector skips the namespace", mayUseCase{
		pool:      testPool{cidr: v4Pool1},
		selectors: fixedSelectors{node: true},
	}),
	Entry("not a named pool that doesn't allow the use", mayUseCase{
		pool:      testPool{cidr: v4Pool1, uses: []v3.IPPoolAllowedUse{v3.IPPoolAllowedUseTunnel}},
		pools:     []string{v4Pool1},
		selectors: fixedSelectors{untouchable: true},
	}),
	Entry("an IPv6 pool whose selectors match, when the claim names only IPv4 pools", mayUseCase{
		pool:      testPool{cidr: v6Pool1},
		pools:     []string{v4Pool1},
		selectors: fixedSelectors{node: true, namespace: true},
		want:      true,
	}),
	Entry("not an IPv6 pool whose node selector skips the node, when the claim names only IPv4 pools", mayUseCase{
		pool:      testPool{cidr: v6Pool1},
		pools:     []string{v4Pool1},
		selectors: fixedSelectors{namespace: true},
	}),
	Entry("not an IPv6 pool the claim doesn't name, when it names pools of both families", mayUseCase{
		pool:      testPool{cidr: v6Pool2},
		pools:     []string{v4Pool1, v6Pool1},
		selectors: fixedSelectors{untouchable: true},
	}),
)

var _ = Describe("PoolClaim.MayUse errors", func() {
	It("returns a selector's error, and false", func() {
		pool := testPool{cidr: v4Pool1}.build()
		claim := NewPoolClaim(v3.IPPoolAllowedUseWorkload, nil, fixedSelectors{untouchable: true})
		ok, err := claim.MayUse(&pool)
		Expect(err).To(MatchError(errSelectorsConsulted))
		Expect(ok).To(BeFalse())
	})

	It("needs no selectors for a claim that names its pools", func() {
		pool := testPool{cidr: v4Pool1}.build()
		claim := NewPoolClaim(v3.IPPoolAllowedUseWorkload, parseRequestedPools(v4Pool1), nil)
		Expect(claim.MayUse(&pool)).To(BeTrue())
	})

	It("returns an error, and false, for a claim that names no pool and has no selectors", func() {
		pool := testPool{cidr: v4Pool1, manual: true}.build()
		claim := NewPoolClaim(v3.IPPoolAllowedUseWorkload, nil, nil)
		ok, err := claim.MayUse(&pool)
		Expect(err).To(MatchError(errClaimWithoutSelectors))
		Expect(ok).To(BeFalse())
	})

	It("needs selectors for a pool in a family the claim names no pool in", func() {
		pool := testPool{cidr: v6Pool1}.build()
		claim := NewPoolClaim(v3.IPPoolAllowedUseWorkload, parseRequestedPools(v4Pool1), nil)
		ok, err := claim.MayUse(&pool)
		Expect(err).To(MatchError(errClaimWithoutSelectors))
		Expect(ok).To(BeFalse())
	})
})

// resolveCase is one row of the ResolvePools table, resolving against pool-a (10.0.0.0/24), pool-b (20.0.0.0/24),
// a pool with no name (30.0.0.0/24), and pool-v6 (5001:0:0:1a::/64).
type resolveCase struct {
	entries []string
	version int
	want    []string
	err     string
}

var _ = DescribeTable("ResolvePools",
	func(tc resolveCase) {
		pools := buildPools([]testPool{{cidr: "10.0.0.0/24"}, {cidr: "20.0.0.0/24"}, {cidr: "30.0.0.0/24"}, {cidr: v6Pool1}})
		pools[0].Name = "pool-a"
		pools[1].Name = "pool-b"
		pools[2].Name = ""
		pools[3].Name = "pool-v6"

		resolved, err := ResolvePools(pools, tc.entries, tc.version)
		if tc.err != "" {
			Expect(err).To(MatchError(tc.err))
			return
		}
		Expect(err).NotTo(HaveOccurred())
		got := []string{}
		for _, r := range resolved {
			got = append(got, r.String())
		}
		Expect(got).To(Equal(tc.want))
	},
	Entry("no entries", resolveCase{
		version: 4,
		want:    []string{},
	}),
	Entry("names and CIDRs, in the order given", resolveCase{
		entries: []string{"pool-b", "10.0.0.0/24"},
		version: 4,
		want:    []string{"20.0.0.0/24", "10.0.0.0/24"},
	}),
	Entry("a CIDR written with host bits set", resolveCase{
		entries: []string{"10.0.0.1/24"},
		version: 4,
		want:    []string{"10.0.0.0/24"},
	}),
	Entry("an IPv6 pool by name and by CIDR", resolveCase{
		entries: []string{"pool-v6", "5001:0:0:1a::/64"},
		version: 6,
		want:    []string{"5001:0:0:1a::/64", "5001:0:0:1a::/64"},
	}),
	Entry("a name no pool has", resolveCase{
		entries: []string{"pool-a", "pool-c"},
		version: 4,
		err:     `no IP pool has name or CIDR "pool-c"`,
	}),
	Entry("a CIDR inside a pool but not equal to it", resolveCase{
		entries: []string{"10.0.0.0/26"},
		version: 4,
		err:     `no IP pool has name or CIDR "10.0.0.0/26"`,
	}),
	Entry("an empty entry, even though a pool has no name", resolveCase{
		entries: []string{""},
		version: 4,
		err:     `no IP pool has name or CIDR ""`,
	}),
	Entry("an IPv6 pool's name, resolving IPv4 pools", resolveCase{
		entries: []string{"pool-a", "pool-v6"},
		version: 4,
		err:     `IP pool "pool-v6" is not an IPv4 pool`,
	}),
	Entry("an IPv4 pool's CIDR, resolving IPv6 pools", resolveCase{
		entries: []string{"10.0.0.0/24"},
		version: 6,
		err:     `IP pool "10.0.0.0/24" is not an IPv6 pool`,
	}),
)

// keepCase is one row of the release-time keepsBlock table, for a node labeled foo=bar and an empty block.
type keepCase struct {
	pools []testPool
	block string
	kept  bool
}

var _ = DescribeTable("nodeKeepsBlock",
	func(tc keepCase) {
		node := internalapi.Node{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"foo": "bar"}}}
		kept, err := nodeKeepsBlock(node, buildPools(tc.pools), cnet.MustParseNetwork(tc.block))
		Expect(err).NotTo(HaveOccurred())
		Expect(kept).To(Equal(tc.kept))
	},
	Entry("releases a block whose only covering pool skips the node", keepCase{
		pools: []testPool{{cidr: "10.0.0.0/24", nodeSelector: `foo != "bar"`}},
		block: "10.0.0.0/26",
	}),
	Entry("keeps a block whose covering pool selects the node", keepCase{
		pools: []testPool{{cidr: "10.0.0.0/24"}},
		block: "10.0.0.0/26",
		kept:  true,
	}),
	Entry("keeps a block an overlapping pool selects, when the pool that skips the node comes first", keepCase{
		pools: []testPool{{cidr: "10.0.0.0/24", nodeSelector: `foo != "bar"`}, {cidr: "10.0.0.0/16"}},
		block: "10.0.0.0/26",
		kept:  true,
	}),
	Entry("keeps a block an overlapping pool selects, when the selecting pool comes first", keepCase{
		pools: []testPool{{cidr: "10.0.0.0/16"}, {cidr: "10.0.0.0/24", nodeSelector: `foo != "bar"`}},
		block: "10.0.0.0/26",
		kept:  true,
	}),
	Entry("keeps a block no enabled pool covers", keepCase{
		pools: []testPool{{cidr: "20.0.0.0/24", nodeSelector: `foo != "bar"`}},
		block: "10.0.0.0/26",
		kept:  true,
	}),
	Entry("keeps a block whose covering pool has a node selector that doesn't parse", keepCase{
		pools: []testPool{{cidr: "10.0.0.0/24", nodeSelector: "invalid selector syntax ["}},
		block: "10.0.0.0/26",
		kept:  true,
	}),
)
