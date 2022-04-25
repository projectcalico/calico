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
	. "github.com/projectcalico/calico/typha/pkg/k8s"

	"context"
	"errors"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/typha/pkg/config"
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
