// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.

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
	"net/http"
	"os/exec"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/libcalico-go/lib/health"
)

var _ = Describe("calculation graph scale test", func() {

	var (
		clientset *kubernetes.Clientset
		nsPrefix  string
	)

	BeforeEach(func() {
		log.Info(">>> BeforeEach <<<")
		clientset = initialize(k8sServerEndpoint)
		nsPrefix = getNamespacePrefix()
	})

	It("should run label rotation test", func() {
		Expect(rotateLabels(clientset, nsPrefix)).To(BeNil())
	})

	It("should process 1000 pods", func() {
		Expect(create1000Pods(clientset, nsPrefix)).To(BeNil())
	})

	It("health endpoint should indicate not ready", func() {
		// Because there is no config for the local node.
		triggerFelixRestart()
		for i := 0; i < 20; i++ {
			Expect(getHealthStatus("readiness")()).To(BeNumerically("==", health.StatusBad))
			time.Sleep(500 * time.Millisecond)
		}
	})

	It("health endpoint should indicate not live", func() {
		// Because there is no config for the local node.
		triggerFelixRestart()
		for i := 0; i < 20; i++ {
			Expect(getHealthStatus("liveness")()).To(BeNumerically("==", health.StatusBad))
			time.Sleep(500 * time.Millisecond)
		}
	})

	Context("with a local host", func() {
		BeforeEach(func() {
			triggerFelixRestart()
			_ = NewDeployment(clientset, 0, true)
		})

		It("should see health readiness endpoint", func() {
			Eventually(getHealthStatus("readiness"), "20s", "0.5s").Should(BeNumerically("==", health.StatusGood))
		})

		It("should see health liveness endpoint", func() {
			Eventually(getHealthStatus("liveness"), "20s", "0.5s").Should(BeNumerically("==", health.StatusGood))
		})
	})

	AfterEach(func() {
		log.Info(">>> AfterEach <<<")
		time.Sleep(10 * time.Second)
		cleanupAll(clientset, nsPrefix)
	})
})

func getHealthStatus(endpoint string) func() int {
	return func() int {
		resp, err := http.Get("http://" + felixIP + ":9099/" + endpoint)
		if err != nil {
			log.WithError(err).Error("HTTP GET failed")
			return health.StatusBad
		}
		log.WithField("resp", resp).Info("Health response")
		defer resp.Body.Close()
		return resp.StatusCode
	}
}

func triggerFelixRestart() {
	exec.Command("pkill", "-TERM", "calico-felix").Run()
	time.Sleep(1 * time.Second)
}
