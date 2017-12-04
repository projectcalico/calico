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

	"github.com/projectcalico/felix/fv/containers"
	"github.com/projectcalico/felix/fv/metrics"
	"github.com/projectcalico/felix/fv/utils"
	"github.com/projectcalico/felix/fv/workload"
	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/client"
)

var _ = Context("Config update tests, after starting felix", func() {

	var (
		etcd            *containers.Container
		felix           *containers.Container
		felixInitialPID int
		client          *client.Client
		w               [3]*workload.Workload
	)

	getFelixPIDs := func() []int {
		return felix.GetPIDs("calico-felix")
	}

	updateFelixPID := func() {
		// Get Felix's PID.  This retry loop ensures that we don't get tripped up if we see multiple
		// PIDs, which can happen transiently when Felix forks off a subprocess.
		start := time.Now()
		for {
			pids := getFelixPIDs()
			if len(pids) == 1 {
				felixInitialPID = pids[0]
				break
			}
			Expect(time.Since(start)).To(BeNumerically("<", time.Second))
		}
	}

	BeforeEach(func() {
		etcd = containers.RunEtcd()

		client = utils.GetEtcdClient(etcd.IP)
		Eventually(client.EnsureInitialized, "10s", "1s").ShouldNot(HaveOccurred())

		felix = containers.RunFelix(etcd.IP)

		felixNode := api.NewNode()
		felixNode.Metadata.Name = felix.Hostname
		_, err := client.Nodes().Create(felixNode)
		Expect(err).NotTo(HaveOccurred())

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
		Consistently(getFelixPIDs, "3s", "200ms").Should(ContainElement(felixInitialPID))
		// We know the initial PID has continued to be active, check that none of the extra
		// transientPIDs we see are long-lived.
		Eventually(getFelixPIDs).Should(ConsistOf(felixInitialPID))
	}

	It("should stay up >2s", shouldStayUp)

	updateConfig := func() {
		err := client.Config().SetFelixConfig("ClusterGUID", "", "foobarbaz")
		Expect(err).NotTo(HaveOccurred())
		err = client.Config().SetFelixConfig("ClusterType", "", "felix-fv,something-new")
		Expect(err).NotTo(HaveOccurred())
		err = client.Config().SetFelixConfig("CalicoVersion", "", "v3.0")
		Expect(err).NotTo(HaveOccurred())
		err = client.Config().SetFelixConfig("ClusterGUID", felix.Hostname, "foobarbaz")
		Expect(err).NotTo(HaveOccurred())
		err = client.Config().SetFelixConfig("ClusterType", felix.Hostname, "felix-fv,something-new")
		Expect(err).NotTo(HaveOccurred())
		err = client.Config().SetFelixConfig("CalicoVersion", felix.Hostname, "v3.0")
		Expect(err).NotTo(HaveOccurred())
	}

	Context("after updating config that felix can handle", func() {
		BeforeEach(updateConfig)

		It("should stay up >2s", shouldStayUp)

		Context("after deleting config that felix can handle", func() {
			BeforeEach(func() {
				err := client.Config().SetFelixConfig("ClusterGUID", "", "")
				Expect(err).NotTo(HaveOccurred())
				err = client.Config().SetFelixConfig("ClusterType", "", "")
				Expect(err).NotTo(HaveOccurred())
				err = client.Config().SetFelixConfig("CalicoVersion", "", "")
				Expect(err).NotTo(HaveOccurred())
				err = client.Config().SetFelixConfig("ClusterGUID", felix.Hostname, "")
				Expect(err).NotTo(HaveOccurred())
				err = client.Config().SetFelixConfig("ClusterType", felix.Hostname, "")
				Expect(err).NotTo(HaveOccurred())
				err = client.Config().SetFelixConfig("CalicoVersion", felix.Hostname, "")
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

	Context("after updating config that should trigger a restart", func() {
		BeforeEach(func() {
			err := client.Config().SetFelixConfig("InterfacePrefix", "", "foo")
			Expect(err).NotTo(HaveOccurred())
		})

		shouldDieAfterAWhile := func() {
			// Felix has a 2s timer before it restarts so we should see the same PID for a while.
			Consistently(getFelixPIDs, "1s", "100ms").Should(ContainElement(felixInitialPID))
			// TODO(smc) When porting this test to v3.0, need to check felix restarts without killing container.
			Eventually(felix.ListedInDockerPS, "5s", "100ms").Should(BeFalse())
		}

		It("should exit after a delay", shouldDieAfterAWhile)

		Context("after restart", func() {

			BeforeEach(func() {
				Eventually(felix.ListedInDockerPS, "5s", "100ms").Should(BeFalse())
				felix.Stop()

				felix = containers.RunFelix(etcd.IP)
				updateFelixPID()
			})

			It("should stay up until we delete the config again", func() {
				shouldStayUp()

				err := client.Config().UnsetFelixConfig("InterfacePrefix", "")
				Expect(err).NotTo(HaveOccurred())

				shouldDieAfterAWhile()
			})
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
