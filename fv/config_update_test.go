// +build fvtests

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

package fv_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"time"

	"context"

	"github.com/projectcalico/felix/fv/containers"
	"github.com/projectcalico/felix/fv/metrics"
	"github.com/projectcalico/felix/fv/workload"
	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/libcalico-go/lib/options"
)

var _ = Context("Config update tests, after starting felix", func() {

	var (
		etcd     *containers.Container
		felix    *containers.Container
		felixPID int
		client   client.Interface
		w        [3]*workload.Workload
	)

	getFelixPIDs := func() []int {
		return felix.GetPIDs("calico-felix")
	}

	updateFelixPID := func() {
		// Get Felix's PID.  This retry loop ensures that we don't get tripped up if we see multiple
		// PIDs, which can happen transiently when Felix restarts/forks off a subprocess.
		start := time.Now()
		for {
			pids := getFelixPIDs()
			if len(pids) == 1 {
				felixPID = pids[0]
				break
			}
			Expect(time.Since(start)).To(BeNumerically("<", time.Second))
			time.Sleep(50 * time.Millisecond)
		}
	}

	BeforeEach(func() {
		felix, etcd, client = containers.StartSingleNodeEtcdTopology()
		updateFelixPID()
	})

	AfterEach(func() {

		if CurrentGinkgoTestDescription().Failed {
			felix.Exec("iptables-save", "-c")
			felix.Exec("ip", "r")
		}

		for ii := range w {
			w[ii].Stop()
		}
		felix.Stop()

		if CurrentGinkgoTestDescription().Failed {
			etcd.Exec("etcdctl", "ls", "--recursive", "/")
		}
		etcd.Stop()
	})

	shouldStayUp := func() {
		// Felix has a 2s timer before it restarts so need to monitor for > 2s.
		// We use ContainElement because Felix regularly forks off subprocesses and those
		// subprocesses initially have name "calico-felix".
		Consistently(getFelixPIDs, "3s", "200ms").Should(ContainElement(felixPID))
		// We know the initial PID has continued to be active, check that none of the extra
		// transientPIDs we see are long-lived.
		Eventually(getFelixPIDs).Should(ConsistOf(felixPID))
	}

	It("should stay up >2s", shouldStayUp)

	updateConfig := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err := client.EnsureInitialized(ctx, "a-new-version", "updated-type")
		Expect(err).NotTo(HaveOccurred())
	}

	Context("after updating config that felix can handle", func() {
		BeforeEach(updateConfig)

		It("should stay up >2s", shouldStayUp)

		Context("after deleting config that felix can handle", func() {
			BeforeEach(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()

				ci, err := client.ClusterInformation().Get(ctx, "default", options.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				ci.Spec.ClusterGUID = ""
				ci.Spec.CalicoVersion = ""
				ci.Spec.ClusterType = ""
				_, err = client.ClusterInformation().Update(ctx, ci, options.SetOptions{})
				Expect(err).NotTo(HaveOccurred())
			})

			It("should stay up >2s", shouldStayUp)
		})
	})

	Context("after waiting for felix to come into sync and then updating config", func() {
		BeforeEach(func() {
			waitForFelixInSync(felix)
			updateConfig()
		})

		It("should stay up >2s", shouldStayUp)
	})

	shouldExitAfterADelay := func() {
		Consistently(getFelixPIDs, "1s", "100ms").Should(ContainElement(felixPID))
		Eventually(getFelixPIDs, "10s", "100ms").ShouldNot(ContainElement(felixPID))
	}

	Context("after updating config that should trigger a restart", func() {
		var config *api.FelixConfiguration

		BeforeEach(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			config = api.NewFelixConfiguration()
			config.Name = "default"
			config.Spec.InterfacePrefix = "foobarbaz"

			var err error
			config, err = client.FelixConfigurations().Create(ctx, config, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		It("should exit after a delay", shouldExitAfterADelay)

		Context("after deleting config that should trigger a restart", func() {
			BeforeEach(func() {
				// Wait for the add to register and cause a restart.
				Eventually(getFelixPIDs, "5s", "100ms").ShouldNot(ContainElement(felixPID))
				updateFelixPID()

				// Then remove the config that we added.
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				config.Spec.InterfacePrefix = ""
				_, err := client.FelixConfigurations().Update(ctx, config, options.SetOptions{})
				Expect(err).NotTo(HaveOccurred())
			})

			It("should exit after a delay", shouldExitAfterADelay)
		})
	})
})

func waitForFelixInSync(felix *containers.Container) {
	// The datastore should transition to in-sync.
	Eventually(func() (int, error) {
		return metrics.GetFelixMetricInt(felix.IP, "felix_resync_state")
	}).Should(Equal(3 /* in-sync */))
	// And then we should see at least one apply to the dataplane.
	Eventually(func() (int, error) {
		return metrics.GetFelixMetricInt(felix.IP, "felix_int_dataplane_apply_time_seconds_count")
	}).Should(BeNumerically(">", 0))
}
