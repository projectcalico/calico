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

package main

import (
	"flag"
	"math/rand"
	"time"

	log "github.com/Sirupsen/logrus"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"k8s.io/client-go/kubernetes"
)

var _ = Describe("testing the test code", func() {

	It("should get non-nil value from getMac", func() {
		m := getMac()
		log.WithField("mac", m).Info("Generated MAC address")
		Expect(m).ToNot(BeNil())
	})
})

var _ = Context("with a k8s clientset", func() {

	var (
		clientset *kubernetes.Clientset
		nsPrefix  string
		d         deployment
	)

	BeforeEach(func() {
		clientset = initialize(flag.Arg(0))
		nsPrefix = getNamespacePrefix()
	})

	AfterEach(func() {
		time.Sleep(10 * time.Second)
		cleanupAll(clientset, nsPrefix)
	})

	Context("with 1 remote node", func() {

		BeforeEach(func() {
			d = NewDeployment(1, false)
		})

		It("should create 10k endpoints", func() {
			addNamespaces(clientset, nsPrefix)
			addEndpoints(clientset, nsPrefix, d, 10000)
		})

		It("should not leak memory", func() {
			addNamespaces(clientset, nsPrefix)
			for ii := 0; ii < 10; ii++ {
				addEndpoints(clientset, nsPrefix, d, 10000)
				time.Sleep(20 * time.Second)
				cleanupAllPods(clientset, nsPrefix)
				time.Sleep(20 * time.Second)
			}
		})
	})

	Context("with 1 local node", func() {

		BeforeEach(func() {
			d = NewDeployment(0, true)
		})

		It("should handle a local endpoint", func() {
			createNamespace(clientset, nsPrefix+"test", nil)
			createPod(clientset, d, nsPrefix+"test", podSpec{})
			time.Sleep(10 * time.Second)
		})

		It("should handle 10 local endpoints", func() {
			createNamespace(clientset, nsPrefix+"test", nil)
			for ii := 0; ii < 10; ii++ {
				createPod(clientset, d, nsPrefix+"test", podSpec{})
			}
			time.Sleep(10 * time.Second)
		})

		It("should handle 100 local endpoints", func() {
			createNamespace(clientset, nsPrefix+"test", nil)
			for ii := 0; ii < 100; ii++ {
				createPod(clientset, d, nsPrefix+"test", podSpec{})
			}
			time.Sleep(10 * time.Second)
		})

	})

	Context("with 1 local and 9 remote nodes", func() {

		BeforeEach(func() {
			d = NewDeployment(9, true)
		})

		It("should add and remove 1000 pods, of which about 100 on local node", func() {
			createNamespace(clientset, nsPrefix+"scale", nil)
			for cycle := 0; cycle < 10; cycle++ {
				for ii := 0; ii < 1000; ii++ {
					createPod(clientset, d, nsPrefix+"scale", podSpec{})
					time.Sleep(time.Duration(rand.Intn(100)) * time.Millisecond)
				}
				time.Sleep(5 * time.Second)
				cleanupAllPods(clientset, nsPrefix)
				time.Sleep(1 * time.Second)
			}
			time.Sleep(20 * time.Second)
		})
	})
})
