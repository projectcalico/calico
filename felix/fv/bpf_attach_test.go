// Copyright (c) 2021 Tigera, Inc. All rights reserved.
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

package fv

import (
	"os"
	"regexp"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
)

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ Felix bpf reattach object", []apiconfig.DatastoreType{apiconfig.EtcdV3}, func(getInfra infrastructure.InfraFactory) {

	if os.Getenv("FELIX_FV_ENABLE_BPF") != "true" {
		// Non-BPF run.
		return
	}

	var (
		infra   infrastructure.DatastoreInfra
		felixes []*infrastructure.Felix
	)

	BeforeEach(func() {
		infra = getInfra()
		//opts := infrastructure.DefaultTopologyOptions()
		opts := infrastructure.TopologyOptions{
			FelixLogSeverity: "debug",
			DelayFelixStart:  true,
			ExtraEnvVars: map[string]string{
				"FELIX_BPFENABLED":              "true",
				"FELIX_DEBUGDISABLELOGDROPPING": "true",
			},
		}

		felixes, _ = infrastructure.StartNNodeTopology(1, opts, infra)

		err := infra.AddAllowToDatastore("host-endpoint=='true'")
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			infra.DumpErrorData()
		}

		for _, felix := range felixes {
			felix.Stop()
		}

		infra.Stop()
	})

	It("should not reattach bpf programs", func() {
		felix := felixes[0]

		// This should not happen at initial execution of felix, since there is no program attached
		firstRunBase := felix.WatchStdoutFor(regexp.MustCompile("Program already attached, skip reattaching"))
		// These should happen at first execution of felix, since there is no program attached
		firstRunProg1 := felix.WatchStdoutFor(regexp.MustCompile("Continue with attaching BPF program to_hep_debug(|_co-re)\\.o"))
		firstRunProg2 := felix.WatchStdoutFor(regexp.MustCompile("Continue with attaching BPF program from_hep_fib_debug(|_co-re)\\.o"))
		By("Starting Felix")
		felix.TriggerDelayedStart()
		Eventually(firstRunProg1, "10s", "100ms").Should(BeClosed())
		Eventually(firstRunProg2, "10s", "100ms").Should(BeClosed())
		Expect(firstRunBase).NotTo(BeClosed())

		// This should not happen at initial execution of felix, since there is no program attached
		secondRunBase := felix.WatchStdoutFor(regexp.MustCompile("Continue with attaching BPF program"))
		// These should happen after restart of felix, since BPF programs are already attached
		secondRunProg1 := felix.WatchStdoutFor(regexp.MustCompile("Program already attached to TC, skip reattaching to_hep_debug(|_co-re)\\.o"))
		secondRunProg2 := felix.WatchStdoutFor(regexp.MustCompile("Program already attached to TC, skip reattaching from_hep_fib_debug(|_co-re)\\.o"))
		By("Restarting Felix")
		felix.Restart()
		Eventually(secondRunProg1, "10s", "100ms").Should(BeClosed())
		Eventually(secondRunProg2, "10s", "100ms").Should(BeClosed())
		Expect(secondRunBase).NotTo(BeClosed())
	})
})
