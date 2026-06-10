// Copyright (c) 2017,2020 Tigera, Inc. All rights reserved.
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

package k8s_test

import (
	"context"
	"errors"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/typha/pkg/config"
	. "github.com/projectcalico/calico/typha/pkg/k8s"
	"github.com/projectcalico/calico/typha/pkg/rolemanager"
)

var _ = DescribeTable("CalculateMaxConnLimit tests",
	func(numTyphas, numNodes, expectedNumber int, expectedReason string) {
		configParams := &config.Config{
			MaxConnectionsLowerLimit: 11,
			MaxConnectionsUpperLimit: 101,
		}
		num, reason := CalculateMaxConnLimit(configParams, numTyphas, numNodes, 3)
		Expect(num).To(Equal(expectedNumber))
		Expect(reason).To(Equal(expectedReason))
	},
	Entry("Single Typha", 1, 10, 101, "lone typha"),
	Entry("Lower limit", 10, 10, 11, "configured lower limit"),
	Entry("Fraction", 10, 500, 101, "configured upper limit"),
	Entry("Upper limit", 2, 500, 101, "configured upper limit"),
)

var _ = DescribeTable("CalculateMaxConnLimitForTier (two-tier math)",
	func(servingTier rolemanager.Role, counts TierConnCounts, expectedNumber int, expectedReason string) {
		configParams := &config.Config{
			MaxConnectionsLowerLimit: 11,
			MaxConnectionsUpperLimit: 10000,
		}
		num, reason := CalculateMaxConnLimitForTier(configParams, servingTier, counts)
		Expect(num).To(Equal(expectedNumber))
		Expect(reason).To(Equal(expectedReason))
	},
	// Single-tier mode (NumTier1=0): leader serves leaf clients, math matches the
	// original CalculateMaxConnLimit over (NumTier2+1) servers.  With 5 tier2 + the
	// leader = 6 servers, 100 nodes, 4 syncers: 4*(1 + 100*120/5/100) = 4*25 = 100.
	Entry("single-tier leader serves leaves",
		rolemanager.Leader,
		TierConnCounts{NumNodes: 100, NumTier1: 0, NumTier2: 5, NumSyncer: 4},
		100, "fraction+20%"),

	// Two-tier leaf: 1M nodes / 5000 tier2 typhas.  expected = 1e6*4 = 4e6 clients
	// over 5000 peers: 1 + 4e6*120/4999/100 ≈ 1 + 960 = 961.
	Entry("tier2 serving leaves at scale",
		rolemanager.Tier2,
		TierConnCounts{NumNodes: 1_000_000, NumTier1: 100, NumTier2: 5000, NumSyncer: 4},
		961, "fraction+20%"),

	// Two-tier tier1: 5000 tier2 typhas × 4 syncers = 20000 upstream conns over
	// 100 tier1 peers: 1 + 20000*120/99/100 ≈ 1 + 242 = 243.
	Entry("tier1 serving tier2 at scale",
		rolemanager.Tier1,
		TierConnCounts{NumNodes: 1_000_000, NumTier1: 100, NumTier2: 5000, NumSyncer: 4},
		243, "fraction+20%"),

	// Two-tier leader: serves the tier1 typhas; single leader (peers=1) so it gets
	// the upper limit (it must accept all tier1 connections).
	Entry("leader serving tier1 (lone server)",
		rolemanager.Leader,
		TierConnCounts{NumNodes: 1_000_000, NumTier1: 100, NumTier2: 5000, NumSyncer: 4},
		10000, "lone server in tier"),

	// Two-tier tier1 with a single tier1 typha: lone server gets upper limit.
	Entry("tier1 lone server",
		rolemanager.Tier1,
		TierConnCounts{NumNodes: 1000, NumTier1: 1, NumTier2: 50, NumSyncer: 4},
		10000, "lone server in tier"),

	// Small two-tier deployment hits the lower limit: 10 nodes / 3 tier2 typhas.
	// expected = 10*4 = 40 over 3 peers: 1 + 40*120/2/100 = 1 + 24 = 25 < lower(11)?
	// No, 25 > 11, so fraction wins at 25.
	Entry("small tier2 fraction above lower",
		rolemanager.Tier2,
		TierConnCounts{NumNodes: 10, NumTier1: 2, NumTier2: 3, NumSyncer: 4},
		25, "fraction+20%"),
)

var _ = Describe("Poll loop tests", func() {
	var tickerC chan time.Time
	var cxt context.Context
	var cancelFn context.CancelFunc
	var server *dummyServer
	var k8sAPI *dummyK8sAPI

	BeforeEach(func() {
		tickerC = make(chan time.Time)
		cxt, cancelFn = context.WithCancel(context.Background())
		configParams := &config.Config{
			K8sNamespace:             "ns",
			K8sServiceName:           "svc",
			K8sPortName:              "port",
			MaxConnectionsUpperLimit: 101,
			MaxConnectionsLowerLimit: 11,
		}
		k8sAPI = &dummyK8sAPI{
			numTyphas: 5,
			numNodes:  100,
		}
		server = &dummyServer{}
		go func() {
			defer GinkgoRecover()
			PollK8sForConnectionLimit(cxt, configParams, tickerC, k8sAPI, server, 3)
		}()
	})

	AfterEach(func() {
		cancelFn()
	})

	It("should emit on first tick", func() {
		tickerC <- time.Now()
		cancelFn()
		Eventually(server.MaxConns).Should(Equal([]int{93}))
	})
	It("should squash dupes", func() {
		tickerC <- time.Now()
		tickerC <- time.Now()
		tickerC <- time.Now()
		Eventually(server.MaxConns).Should(Equal([]int{93}))
	})
	It("should responds to changes", func() {
		tickerC <- time.Now()
		Eventually(server.MaxConns).Should(Equal([]int{93}))
		k8sAPI.numNodes = 200
		tickerC <- time.Now()
		Eventually(server.MaxConns).Should(Equal([]int{93, 101}))
	})
	It("should increase limit to maximum on GetNumTyphas error", func() {
		tickerC <- time.Now()
		Eventually(server.MaxConns).Should(Equal([]int{93}))
		k8sAPI.numTyphasErr = errors.New("bad typha!")
		tickerC <- time.Now()
		Eventually(server.MaxConns).Should(Equal([]int{93, 101}))
	})
	It("should increase limit to maximum on GetNumNodes error", func() {
		tickerC <- time.Now()
		Eventually(server.MaxConns).Should(Equal([]int{93}))
		k8sAPI.numNodesErr = errors.New("bad nodes!")
		tickerC <- time.Now()
		Eventually(server.MaxConns).Should(Equal([]int{93, 101}))
	})
})

type dummyServer struct {
	L       sync.Mutex
	targets []int
}

func (s *dummyServer) SetMaxConns(numConns int) {
	s.L.Lock()
	defer s.L.Unlock()
	s.targets = append(s.targets, numConns)
}

func (s *dummyServer) MaxConns() []int {
	s.L.Lock()
	defer s.L.Unlock()
	return s.targets
}

type dummyK8sAPI struct {
	numTyphas    int
	numTyphasErr error
	numNodes     int
	numNodesErr  error
}

func (d *dummyK8sAPI) GetNumTyphas(ctx context.Context, namespace, serviceName, portName string) (int, error) {
	Expect(namespace).To(Equal("ns"))
	Expect(serviceName).To(Equal("svc"))
	Expect(portName).To(Equal("port"))
	return d.numTyphas, d.numTyphasErr
}
func (d *dummyK8sAPI) GetNumNodes() (int, error) {
	return d.numNodes, d.numNodesErr
}
