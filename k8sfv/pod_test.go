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
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"k8s.io/client-go/kubernetes"
)

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

		// Test for https://github.com/projectcalico/libcalico-go/pull/375.
		It("should delete a pod whose IP has been cleared", func() {
			time.Sleep(3 * time.Second)
			nsName := nsPrefix + "1"
			createNamespace(clientset, nsName, nil)

			// Create pod.
			podOut := createPod(clientset, d, nsName, podSpec{})

			// Check that Felix sees the endpoint.
			Eventually(getNumEndpointsDefault(-1), "10s", "1s").Should(BeNumerically("==", 1))

			// Clear the pod's IP address.
			podOut.Status.PodIP = ""
			_, err := clientset.Pods(nsName).UpdateStatus(podOut)
			panicIfError(err)

			// Short wait, then delete the pod.
			time.Sleep(1 * time.Second)
			cleanupAllPods(clientset, nsName)

			// Check that Felix saw the deletion.
			Eventually(getNumEndpointsDefault(-1), "10s", "1s").Should(BeNumerically("==", 0))
		})
	})
})
