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
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/ifstate"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	options2 "github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = infrastructure.DatastoreDescribe("Egress SNAT rule renderer", []apiconfig.DatastoreType{apiconfig.EtcdV3, apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	var (
		infra          infrastructure.DatastoreInfra
		felixes        []*infrastructure.Felix
		calicoClient   client.Interface
		w              *workload.Workload
		externalServer *infrastructure.ExternalServer
		egressIP       string
	)

	enableBPF := func() {
		By("Enabling BPF")
		// Update the pre-created felix configuration
		fc, err := calicoClient.FelixConfigurations().Get(context.Background(), "default", options2.GetOptions{})
		bpfEnabled := true
		bpfKubeProxyIptablesCleanupEnabled := false
		if err == nil {
			fc.Spec.BPFEnabled = &bpfEnabled
			fc.Spec.BPFKubeProxyIptablesCleanupEnabled = &bpfKubeProxyIptablesCleanupEnabled
			_, err := calicoClient.FelixConfigurations().Update(context.Background(), fc, options2.SetOptions{})
			Expect(err).NotTo(HaveOccurred(), "Failed to update felix configuration")
		}
		Expect(err).NotTo(HaveOccurred(), "Failed to create felix configuration")
		for _, felix := range felixes {
			ensureBPFProgramsAttached(felix)
		}
	}

	disableBPF := func() {
		By("Disabling BPF")
		// Update the pre-created felix configuration
		fc, err := calicoClient.FelixConfigurations().Get(context.Background(), "default", options2.GetOptions{})
		bpfEnabled := false
		bpfKubeProxyIptablesCleanupEnabled := true
		if err == nil {
			fc.Spec.BPFEnabled = &bpfEnabled
			fc.Spec.BPFKubeProxyIptablesCleanupEnabled = &bpfKubeProxyIptablesCleanupEnabled
			_, err := calicoClient.FelixConfigurations().Update(context.Background(), fc, options2.SetOptions{})
			Expect(err).NotTo(HaveOccurred(), "Failed to update felix configuration")
		}
		Expect(err).NotTo(HaveOccurred(), "Failed to get felix configuration")
	}

	BeforeEach(func() {
		infra = getInfra()
		egressIP = "10.67.0.10"

		egressSNATEnabled := api.EgressSNATEnabled
		fc := api.NewFelixConfiguration()
		fc.Name = "default"
		fc.Spec.EgressSNAT = &egressSNATEnabled
		// fc.Spec.NATOutgoingAddress = egressIP
		options := infrastructure.DefaultTopologyOptions()
		options.InitialFelixConfiguration = fc
		options.NATOutgoingEnabled = true
		felixes, calicoClient = infrastructure.StartNNodeTopology(2, options, infra)

		// Install a default profile that allows all ingress and egress, in the absence of any Policy.
		infra.AddDefaultAllow()

		ippool := api.NewIPPool()
		ippool.Name = "ip-pool-nat-outgoing"
		ippool.Spec.CIDR = "10.67.0.0/24"
		ippool.Spec.NATOutgoing = true
		ippool, err := calicoClient.IPPools().Create(context.Background(), ippool, options2.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Create workload, using that profile.
		w = workload.Run(felixes[1], "w0", "default", "10.65.0.10", "9055", "tcp")
		w.AddEgressSNAT(egressIP)
		w.ConfigureInInfra(infra)

		// We will use this container to model an external server that workloads on
		// host will connect to.  Create a route in felix for the external server.
		externalServer = infrastructure.RunExtServer("ext-server", "default", "10.66.0.220", "8055", "tcp")
		externalServer.SetupRoute()
		externalServer.Exec("ip", "r", "add", "10.67.0.0/24", "via", felixes[0].IP)
		for _, felix := range felixes {
			felix.Exec("ip", "r", "add", "10.66.0.0/24", "via", externalServer.IP)
			// felix.Exec("ip", "addr", "add", egressIP, "dev", "eth0")
		}
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			infra.DumpErrorData()

			fc, err := calicoClient.FelixConfigurations().Get(context.Background(), "default", options2.GetOptions{})
			bpfEnabled := err == nil && *fc.Spec.BPFEnabled
			for _, felix := range felixes {
				felix.Exec("iptables-save", "-c")
				felix.Exec("ip", "r")
				felix.Exec("ip", "a")

				if bpfEnabled {
					felix.Exec("calico-bpf", "routes", "dump")
					felix.Exec("calico-bpf", "conntrack", "dump")
					felix.Exec("calico-bpf", "counters", "dump")
					felix.Exec("calico-bpf", "ifstate", "dump")
				}
			}
		}

		w.Stop()
		for _, felix := range felixes {
			felix.Stop()
		}

		infra.Stop()
		externalServer.Stop()
	})

	It("Linux: Expect outgoing connections from workload uses the configured external IP as source", func() {
		By("disabling BPF mode", disableBPF)
		cc := &connectivity.Checker{}
		cc.ExpectSNAT(w, egressIP, externalServer, 8055)
		cc.CheckConnectivityWithTimeout(3000 * time.Second)
	})

	It("BPF: Expect outgoing connections from workload uses the configured external IP as source", func() {
		By("enabling BPF mode", enableBPF)
		cc := &connectivity.Checker{}
		cc.ExpectSNAT(w, egressIP, externalServer, 8055)
		cc.CheckConnectivityWithTimeout(3000 * time.Second)
	})
})

// Copied from bpf_test
func dumpBPFMap(felix *infrastructure.Felix, m bpf.Map, iter bpf.IterCallback) {
	// Wait for the map to exist before trying to access it.  Otherwise, we
	// might fail a test that was retrying this dump anyway.
	Eventually(func() bool {
		return felix.FileExists(m.Path())
	}, "10s", "300ms").Should(BeTrue(), fmt.Sprintf("dumpBPFMap: map %s didn't show up inside container", m.Path()))
	cmd, err := bpf.DumpMapCmd(m)
	Expect(err).NotTo(HaveOccurred(), "Failed to get BPF map dump command: "+m.Path())
	log.WithField("cmd", cmd).Debug("dumpBPFMap")
	out, err := felix.ExecOutput(cmd...)
	Expect(err).NotTo(HaveOccurred(), "Failed to get dump BPF map: "+m.Path())
	if strings.Contains(m.(*bpf.PinnedMap).Type, "percpu") {
		err = bpf.IterPerCpuMapCmdOutput([]byte(out), iter)
	} else {
		err = bpf.IterMapCmdOutput([]byte(out), iter)
	}
	Expect(err).NotTo(HaveOccurred(), "Failed to parse BPF map dump: "+m.Path())
}

func dumpIfStateMap(felix *infrastructure.Felix) ifstate.MapMem {
	im := ifstate.Map(&bpf.MapContext{})
	m := make(ifstate.MapMem)
	dumpBPFMap(felix, im, ifstate.MapMemIter(m))
	return m
}

func ensureBPFProgramsAttached(felix *infrastructure.Felix, ifacesExtra ...string) {
	ensureBPFProgramsAttachedOffset(2, felix, ifacesExtra...)
}

func ensureBPFProgramsAttachedOffset(offset int, felix *infrastructure.Felix, ifacesExtra ...string) {
	expectedIfaces := []string{"eth0"}

	for _, w := range felix.Workloads {
		if w.Runs() {
			if iface := w.GetInterfaceName(); iface != "" {
				expectedIfaces = append(expectedIfaces, iface)
			}
			if iface := w.GetSpoofInterfaceName(); iface != "" {
				expectedIfaces = append(expectedIfaces, iface)
			}
		}
	}

	expectedIfaces = append(expectedIfaces, ifacesExtra...)

	EventuallyWithOffset(offset, func() []string {
		prog := []string{}
		m := dumpIfStateMap(felix)
		for _, v := range m {
			if (v.Flags() | ifstate.FlgReady) > 0 {
				prog = append(prog, v.IfName())
			}
		}
		return prog
	}, "20s", "200ms").Should(ContainElements(expectedIfaces))
}
