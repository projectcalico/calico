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
	"fmt"
	"math/rand"
	"strconv"

	. "github.com/onsi/gomega"
	"k8s.io/client-go/kubernetes"
)

// This file is a Go translation of scale.py.

func getMac() string {
	// Gets a random mac address.
	return fmt.Sprintf(
		"%02x:%02x:%02x:%02x:%02x:%02x",
		rand.Intn(256),
		rand.Intn(256),
		rand.Intn(256),
		rand.Intn(256),
		rand.Intn(256),
		rand.Intn(256),
	)
}

func addEndpoints(
	clientset *kubernetes.Clientset,
	nsPrefix string,
	d deployment,
	numEndpoints int,
) {
	//last_time = time.Now()
	for i := 0; i < numEndpoints; i++ {
		endpoint_id := fmt.Sprintf("endpoint_%d", i+1)

		ip := fmt.Sprintf("%d.%d.%d.%d",
			[]int{10, 52, 1}[rand.Intn(3)],
			i/65536,
			(i/256)%256,
			i%256,
		)

		nsName := fmt.Sprintf("%s-%03d", nsPrefix, i%1000)
		createPod(clientset, d, nsName, podSpec{
			mac:      getMac(),
			ipv4Addr: ip,
			ipv6Addr: fmt.Sprintf("dead:beef::%x/128", i%65536),
			name:     fmt.Sprintf("%6.6d", i),
			labels: map[string]string{
				"foo":     "bar",
				"alpha":   []string{"a", "b", "c", "d", "e", "f", "g", "h"}[rand.Intn(8)],
				"id":      endpoint_id,
				"mod1000": strconv.Itoa(i % 1000),
				"mod100":  strconv.Itoa(i % 100),
				"mod10":   strconv.Itoa(i % 10),
			},
		})
	}

	Eventually(getNumEndpointsDefault(-1), "30s", "1s").Should(
		BeNumerically("==", numEndpoints),
		"Addition of pods wasn't reflected in Felix metrics",
	)
}

func addNamespaces(clientset *kubernetes.Clientset, nsPrefix string) {
	for ii := 0; ii < 1000; ii++ {
		nsName := fmt.Sprintf("%s-%03d", nsPrefix, ii%1000)
		createNamespace(clientset, nsName, nil)
	}
}
