// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
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

//go:build fvtests

package fv_test

import (
	"context"
	"errors"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"

	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/metrics"
	"github.com/projectcalico/calico/felix/fv/workload"
)

const (
	kubeIPVSInterface     = "kube-ipvs0"
	kubeProxyModeIPVS     = "ipvs"
	kubeProxyModeIptables = "iptables"
)

var _ = Context("Config update tests, after starting felix", func() {

	var (
		etcd          *containers.Container
		felix         *infrastructure.Felix
		felixPID      int
		client        client.Interface
		infra         infrastructure.DatastoreInfra
		w             [3]*workload.Workload
		cfgChangeTime time.Time
	)

	BeforeEach(func() {
		felix, etcd, client, infra = infrastructure.StartSingleNodeEtcdTopology(infrastructure.DefaultTopologyOptions())
		felixPID = felix.GetSinglePID("calico-felix")
	})

	AfterEach(func() {

		if CurrentSpecReport().Failed() {
			felix.Exec("iptables-save", "-c")
			felix.Exec("ip", "r")
		}

		for ii := range w {
			w[ii].Stop()
		}
		felix.Stop()

		if CurrentSpecReport().Failed() {
			etcd.Exec("etcdctl", "get", "/", "--prefix", "--keys-only")
		}
		etcd.Stop()
		infra.Stop()
	})

	shouldStayUp := func() {
		// Felix has a 2s timer before it restarts so need to monitor for > 2s.
		// We use ContainElement because Felix regularly forks off subprocesses and those
		// subprocesses initially have name "calico-felix".
		Consistently(felix.GetFelixPIDs, "3s", "200ms").Should(ContainElement(felixPID))
		// We know the initial PID has continued to be active, check that none of the extra
		// transientPIDs we see are long-lived.
		Eventually(felix.GetFelixPIDs).Should(ConsistOf(felixPID))
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
		// The config delay time is 2s in Felix, so let's check that the config remains the same for at least
		// 1s since the time of the config change.
		monitorTime := time.Second - time.Since(cfgChangeTime)
		if monitorTime > 0 {
			Consistently(felix.GetFelixPIDs, monitorTime, "100ms").Should(ContainElement(felixPID))
		}
		Eventually(felix.GetFelixPIDs, "10s", "100ms").ShouldNot(ContainElement(felixPID))

		// Update felix pid after restart.
		felixPID = felix.GetSinglePID("calico-felix")
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
				Eventually(felix.GetFelixPIDs, "5s", "100ms").ShouldNot(ContainElement(felixPID))
				felixPID = felix.GetSinglePID("calico-felix")

				// Wait for felix to come in to sync; otherwise we may manage to remove the config before
				// felix loads it.
				waitForFelixInSync(felix)

				// Then remove the config that we added.
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()

				// Track the current time and then make the config change.
				cfgChangeTime = time.Now()
				config.Spec.InterfacePrefix = ""
				_, err := client.FelixConfigurations().Update(ctx, config, options.SetOptions{})
				Expect(err).NotTo(HaveOccurred())
			})

			It("should exit after a delay", shouldExitAfterADelay)
		})
	})

	Context("after switching kube-proxy mode that should trigger a restart", func() {
		// This test simulates kube-proxy switching between iptables to ipvs mode by adding/removing
		// kube-ipvs0 dummy interface.
		var proxy *kubeProxy

		BeforeEach(func() {
			waitForFelixInSync(felix)
			proxy = newKubeProxy(felix)
		})

		Context("after switch to ipvs mode that should trigger a restart", func() {
			BeforeEach(func() {
				// Track the current time and then make the config change.
				cfgChangeTime = time.Now()
				err := proxy.switchToMode(kubeProxyModeIPVS)
				Expect(err).NotTo(HaveOccurred())
			})

			It("should exit after a delay", shouldExitAfterADelay)
		})

		Context("after switch to iptables mode that should trigger a restart", func() {
			BeforeEach(func() {
				// Track the current time and then make the config change to ipvs mode
				cfgChangeTime = time.Now()
				err := proxy.switchToMode(kubeProxyModeIPVS)
				Expect(err).NotTo(HaveOccurred())

				// Wait felix in sync again.
				shouldExitAfterADelay()
				waitForFelixInSync(felix)

				// Track the current time and then make the config change back to iptables mode.
				cfgChangeTime = time.Now()
				err = proxy.switchToMode(kubeProxyModeIptables)
				Expect(err).NotTo(HaveOccurred())
			})

			It("should exit after a delay", shouldExitAfterADelay)
		})
	})
})

func waitForFelixInSync(felix *infrastructure.Felix) {
	// The datastore should transition to in-sync.
	Eventually(func() (int, error) {
		return metrics.GetFelixMetricInt(felix.IP, "felix_resync_state")
	}).Should(Equal(3 /* in-sync */))
	// And then we should see at least one apply to the dataplane.
	Eventually(func() (int, error) {
		return metrics.GetFelixMetricInt(felix.IP, "felix_int_dataplane_apply_time_seconds_count")
	}).Should(BeNumerically(">", 0))
}

// kubeProxy object for felix container
type kubeProxy struct {
	mode  string
	felix *infrastructure.Felix
}

func newKubeProxy(felix *infrastructure.Felix) *kubeProxy {
	// Default mode for kube-proxy is iptables.
	return &kubeProxy{mode: "iptables", felix: felix}
}

func (k *kubeProxy) getCurrentMode() string {
	return k.mode
}

func (k *kubeProxy) switchToMode(mode string) error {
	if mode == k.mode {
		// nothing to do
		return nil
	}

	switch mode {
	case kubeProxyModeIPVS:
		k.felix.Exec("ip", "link", "add", "dev", kubeIPVSInterface, "type", "dummy")
		k.felix.Exec("ip", "link", "set", kubeIPVSInterface, "up")
	case kubeProxyModeIptables:
		k.felix.Exec("ip", "link", "del", kubeIPVSInterface)
	default:
		return errors.New("Invalid mode to switch.")
	}

	k.mode = mode
	return nil
}
