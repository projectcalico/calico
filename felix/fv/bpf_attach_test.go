// Copyright (c) 2021-2022 Tigera, Inc. All rights reserved.
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
	"os"
	"regexp"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ Felix bpf reattach object", []apiconfig.DatastoreType{apiconfig.EtcdV3}, func(getInfra infrastructure.InfraFactory) {

	if os.Getenv("FELIX_FV_ENABLE_BPF") != "true" {
		// Non-BPF run.
		return
	}

	var (
		infra        infrastructure.DatastoreInfra
		felix        *infrastructure.Felix
		calicoClient client.Interface
	)

	BeforeEach(func() {
		infra = getInfra()
		// opts := infrastructure.DefaultTopologyOptions()
		opts := infrastructure.TopologyOptions{
			FelixLogSeverity: "debug",
			DelayFelixStart:  true,
			ExtraEnvVars: map[string]string{
				"FELIX_BPFENABLED":              "true",
				"FELIX_DEBUGDISABLELOGDROPPING": "true",
			},
		}

		felixes, cc := infrastructure.StartNNodeTopology(1, opts, infra)
		felix = felixes[0]
		calicoClient = cc

		err := infra.AddAllowToDatastore("host-endpoint=='true'")
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			infra.DumpErrorData()
		}

		felix.Stop()
		infra.Stop()
	})

	It("should not reattach bpf programs after restart", func() {

		// This should not happen at initial execution of felix, since there is no program attached
		firstRunBase := felix.WatchStdoutFor(regexp.MustCompile("Program already attached, skip reattaching"))
		// These should happen at first execution of felix, since there is no program attached
		firstRunProg1 := felix.WatchStdoutFor(regexp.MustCompile(`Continue with attaching BPF program to_hep_fib_debug(|_co-re)\.o`))
		firstRunProg2 := felix.WatchStdoutFor(regexp.MustCompile(`Continue with attaching BPF program from_hep_fib_debug(|_co-re)\.o`))
		By("Starting Felix")
		felix.TriggerDelayedStart()
		Eventually(firstRunProg1, "10s", "100ms").Should(BeClosed())
		Eventually(firstRunProg2, "10s", "100ms").Should(BeClosed())
		Expect(firstRunBase).NotTo(BeClosed())

		// This should not happen at initial execution of felix, since there is no program attached
		secondRunBase := felix.WatchStdoutFor(regexp.MustCompile(`Continue with attaching BPF program (to|from)_hep`))
		// These should happen after restart of felix, since BPF programs are already attached
		secondRunProg1 := felix.WatchStdoutFor(regexp.MustCompile(`Program already attached to TC, skip reattaching to_hep_fib_debug(|_co-re)\.o`))
		secondRunProg2 := felix.WatchStdoutFor(regexp.MustCompile(`Program already attached to TC, skip reattaching from_hep_fib_debug(|_co-re)\.o`))
		By("Restarting Felix")
		felix.Restart()
		Eventually(secondRunProg1, "10s", "100ms").Should(BeClosed())
		Eventually(secondRunProg2, "10s", "100ms").Should(BeClosed())
		Expect(secondRunBase).NotTo(BeClosed())
	})

	It("should not reattach bpf programs when policy changes", func() {
		By("Starting Felix")
		felix.TriggerDelayedStart()

		By("Adding pod")
		wIP := "10.65.0.11"
		w := workload.Run(felix, "pod", "default", wIP, "8055", "tcp")
		w.WorkloadEndpoint.Labels = map[string]string{"name": w.Name}
		w.ConfigureInInfra(infra)

		By("Waiting for all programs ready")
		ensureBPFProgramsAttached(felix)

		progs1, err := felix.ExecOutput("bpftool", "-jp", "net")
		Expect(err).NotTo(HaveOccurred())

		By("Changing policy")
		pol := api.NewGlobalNetworkPolicy()
		pol.Namespace = "fv"
		pol.Name = "policy-1"
		pol.Spec.Ingress = []api.Rule{{Action: "Deny"}}
		pol.Spec.Egress = []api.Rule{{Action: "Deny"}}
		pol.Spec.Selector = "name=='" + w.Name + "'"

		_, err = calicoClient.GlobalNetworkPolicies().Create(utils.Ctx, pol, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		By("Verifying that policy is programmed")
		bpfWaitForPolicy(felix, w.GetInterfaceName(), "ingress", "default.policy-1")
		bpfWaitForPolicy(felix, w.GetInterfaceName(), "egress", "default.policy-1")

		progs2, err := felix.ExecOutput("bpftool", "-jp", "net")
		Expect(err).NotTo(HaveOccurred())

		Expect(progs1).To(Equal(progs2))
	})

	It("should clean up programs when BPFDataIfacePattern changes", func() {
		By("Starting Felix")
		felix.TriggerDelayedStart()

		By("Checking that eth0 has a program")

		Eventually(func() string {
			out, _ := felix.ExecOutput("bpftool", "-jp", "net")
			return out
		}, "15s", "1s").Should(ContainSubstring("eth0"))

		By("Changing env and restarting felix")

		felix.SetEvn(map[string]string{"FELIX_BPFDataIfacePattern": "eth1"})
		felix.Restart()

		By("Checking that eth0 does not have a program anymore")

		Eventually(func() string {
			out, _ := felix.ExecOutput("bpftool", "-jp", "net")
			return out
		}, "15s", "1s").ShouldNot(ContainSubstring("eth0"))
	})
})
