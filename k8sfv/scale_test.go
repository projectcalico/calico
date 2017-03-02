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
	"fmt"
	"math/rand"
	"strconv"
	"time"

	log "github.com/Sirupsen/logrus"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"k8s.io/client-go/kubernetes"
)

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

func addEndpoints(clientset *kubernetes.Clientset, d deployment, numEndpoints int) {
	//last_time = time.Now()
	for i := 0; i < numEndpoints; i++ {
		endpoint_id := fmt.Sprintf("endpoint_%d", i+1)

		ip := fmt.Sprintf("%d.%d.%d.%d",
			[]int{10, 52, 1}[rand.Intn(3)],
			i/65536,
			(i/256)%256,
			i%256,
		)

		nsName := fmt.Sprintf("prof-%03d", i%1000)
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

	return
}

//        if random.random() > 0.5:
//            # Delete first.
//            path = "/calico/v1/host/%s/workload/%s/%s" % (HOST, ORCH, endpoint_id)
//            tmp = subprocess.Popen(["etcdctl",  "rm", "--recursive", path],
//                                   stdout=subprocess.PIPE,
//                                   stderr=subprocess.PIPE)
//        path = "/calico/v1/host/%s/workload/%s/%s/endpoint/%s" % (HOST, ORCH, endpoint_id, endpoint_id)
//        tmp = subprocess.Popen(["etcdctl",  "set", path, json.dumps(data)],
//                               stdout=subprocess.PIPE)
//
//        if (i + 1) % 100 == 0:
//            now = time.time()
//            duration = now - last_time
//            rate = 100 / duration
//            _log.info("Just done endpoint %d (%.1f/s)", i + 1, rate)
//            last_time = now

func addNamespaces(clientset *kubernetes.Clientset) {
	for ii := 0; ii < 1000; ii++ {
		nsName := fmt.Sprintf("prof-%03d", ii%1000)
		createNamespace(clientset, nsName, nil)
	}
	return
}

var _ = Describe("100k scale test", func() {

	var (
		clientset *kubernetes.Clientset
	)

	BeforeEach(func() {
		clientset = initialize(flag.Arg(0))
	})

	It("should get expected value from getMac", func() {
		m := getMac()
		log.WithField("mac", m).Info("Generated MAC address")
		Expect(m).ToNot(BeNil())
	})

	It("should create 100k endpoints", func() {
		d := NewDeployment(1, false)
		addNamespaces(clientset)
		addEndpoints(clientset, d, 100000)
	})

	AfterEach(func() {
		time.Sleep(20 * time.Second)
		cleanupAll(clientset, "prof-")
	})

	It("should not leak memory", func() {
		d := NewDeployment(1, false)
		addNamespaces(clientset)
		for ii := 0; ii < 10; ii++ {
			addEndpoints(clientset, d, 10000)
			time.Sleep(30 * time.Second)
			cleanupAllPods(clientset, "prof-")
			time.Sleep(30 * time.Second)
		}
		cleanupAll(clientset, "prof-")
	})

	It("should handle a local endpoint", func() {
		d := NewDeployment(0, true)
		createPod(clientset, d, "test", podSpec{})
		time.Sleep(3600 * time.Second)
	})

	It("should handle 10 local endpoints", func() {
		d := NewDeployment(0, true)
		for ii := 0; ii < 10; ii++ {
			createPod(clientset, d, "test", podSpec{})
		}
		time.Sleep(3600 * time.Second)
	})

	It("should handle 100 local endpoints", func() {
		d := NewDeployment(0, true)
		for ii := 0; ii < 100; ii++ {
			createPod(clientset, d, "test", podSpec{})
			//time.Sleep(10 * time.Millisecond)
		}
		time.Sleep(3600 * time.Second)
	})

	It("should handle 1000 local endpoints", func() {
		d := NewDeployment(0, true)
		for ii := 0; ii < 1000; ii++ {
			createPod(clientset, d, "test", podSpec{})
			time.Sleep(500 * time.Millisecond)
		}
		time.Sleep(3600 * time.Second)
	})

	It("10 nodes 1000 pods", func() {
		d := NewDeployment(9, true)
		createNamespace(clientset, "scale", nil)
		for cycle := 0; cycle < 10; cycle++ {
			for ii := 0; ii < 1000; ii++ {
				createPod(clientset, d, "scale", podSpec{})
				time.Sleep(time.Duration(rand.Intn(100)) * time.Millisecond)
			}
			time.Sleep(5 * time.Second)
			cleanupAllPods(clientset, "scale")
			time.Sleep(1 * time.Second)
		}
		time.Sleep(3600 * time.Second)
	})
})
