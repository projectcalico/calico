// Copyright (c) 2022 Tigera, Inc. All rights reserved.
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
	"context"
	"fmt"
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf/counters"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	options2 "github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ Felix bpf test counters", []apiconfig.DatastoreType{apiconfig.EtcdV3}, func(getInfra infrastructure.InfraFactory) {
	if !BPFMode() {
		return
	}

	var (
		infra        infrastructure.DatastoreInfra
		tc           infrastructure.TopologyContainers
		calicoClient client.Interface
		w            [2]*workload.Workload
	)

	BeforeEach(func() {
		infra = getInfra()
		opts := infrastructure.DefaultTopologyOptions()
		opts.ExtraEnvVars["FELIX_BPFPolicyDebugEnabled"] = "true"
		tc, calicoClient = infrastructure.StartNNodeTopology(1, opts, infra)
		for i := 0; i < 2; i++ {
			wIP := fmt.Sprintf("10.65.0.%d", i+2)
			w[i] = workload.Run(tc.Felixes[0], fmt.Sprintf("w%d", i), "default", wIP, "8055", "tcp")
			w[i].WorkloadEndpoint.Labels = map[string]string{"name": w[i].Name}
			w[i].ConfigureInInfra(infra)
		}
		ensureBPFProgramsAttached(tc.Felixes[0])
	})

	createPolicy := func(policy *api.GlobalNetworkPolicy) *api.GlobalNetworkPolicy {
		log.WithField("policy", dumpResource(policy)).Info("Creating policy")
		policy, err := calicoClient.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())
		return policy
	}

	updatePolicy := func(policy *api.GlobalNetworkPolicy) *api.GlobalNetworkPolicy {
		log.WithField("policy", dumpResource(policy)).Info("Updating policy")
		policy, err := calicoClient.GlobalNetworkPolicies().Update(utils.Ctx, policy, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())
		return policy
	}

	It("should update generic counters", func() {
		By("ensuring we have counters")
		By("installing a deny policy between workloads")
		pol := api.NewGlobalNetworkPolicy()
		pol.Namespace = "default"
		pol.Name = "drop-workload0-to-workload1"
		pol.Spec.Selector = "all()"
		pol.Spec.Ingress = []api.Rule{
			{
				Action: "Deny",
				Source: api.EntityRule{
					Nets: []string{fmt.Sprintf("%s/32", w[0].IP)},
				},
				Destination: api.EntityRule{
					Nets: []string{fmt.Sprintf("%s/32", w[1].IP)},
				},
			},
			{
				Action: api.Allow,
			},
		}
		pol.Spec.Egress = []api.Rule{{Action: api.Allow}}
		pol = createPolicy(pol)

		bpfWaitForGlobalNetworkPolicy(tc.Felixes[0], w[1].InterfaceName, "ingress", "drop-workload0-to-workload1")

		By("generating packets and checking the counter")
		numberOfpackets := 10
		for i := 0; i < numberOfpackets; i++ {
			_, err := w[0].RunCmd("pktgen", w[0].IP, w[1].IP, "udp", "--port-dst", "8055", "--ip-id", strconv.Itoa(i+1))
			Expect(err).NotTo(HaveOccurred())
			_, err = w[0].RunCmd("pktgen", w[0].IP, tc.Felixes[0].IP, "udp", "--port-dst", "8055")
			Expect(err).NotTo(HaveOccurred())
		}
		Eventually(func(g Gomega) {
			checkDroppedByPolicyCounters(g, tc.Felixes[0], w[1].InterfaceName, 0, numberOfpackets)
		}, "5s", "500ms").Should(Succeed())
	})

	It("should update rule counters", func() {
		pol := api.NewGlobalNetworkPolicy()
		pol.Namespace = "fv"
		pol.Name = "policy-test"
		pol.Spec.Selector = "all()"
		pol.Spec.Ingress = []api.Rule{{Action: "Deny"}}
		pol.Spec.Egress = []api.Rule{{Action: "Deny"}}
		pol = createPolicy(pol)

		Eventually(func() bool {
			return bpfCheckIfGlobalNetworkPolicyProgrammed(tc.Felixes[0], w[0].InterfaceName, "ingress", "policy-test", "deny", true)
		}, "2s", "200ms").Should(BeTrue())

		Eventually(func() bool {
			return bpfCheckIfGlobalNetworkPolicyProgrammed(tc.Felixes[0], w[0].InterfaceName, "egress", "policy-test", "deny", true)
		}, "2s", "200ms").Should(BeTrue())

		Eventually(func() bool {
			return bpfCheckIfGlobalNetworkPolicyProgrammed(tc.Felixes[0], w[1].InterfaceName, "ingress", "policy-test", "deny", true)
		}, "2s", "200ms").Should(BeTrue())

		Eventually(func() bool {
			return bpfCheckIfGlobalNetworkPolicyProgrammed(tc.Felixes[0], w[1].InterfaceName, "egress", "policy-test", "deny", true)
		}, "2s", "200ms").Should(BeTrue())

		for i := 0; i < 10; i++ {
			_, err := w[1].RunCmd("pktgen", w[1].IP, w[0].IP, "udp", "--port-src", "8055", "--port-dst", "8055")
			Expect(err).NotTo(HaveOccurred())
		}
		m := dumpRuleCounterMap(tc.Felixes[0])
		Expect(len(m)).To(Equal(1))
		for _, v := range m {
			Expect(v).To(Equal(uint64(10)))
		}

		checkRuleCounters(tc.Felixes[0], w[1].InterfaceName, "egress", "policy-test", 10)

		pol.Spec.Ingress = []api.Rule{{Action: "Allow"}}
		pol.Spec.Egress = []api.Rule{{Action: "Allow"}}

		pol = updatePolicy(pol)
		Eventually(func() bool {
			return bpfCheckIfGlobalNetworkPolicyProgrammed(tc.Felixes[0], w[0].InterfaceName, "ingress", "policy-test", "allow", true)
		}, "2s", "200ms").Should(BeTrue())

		Eventually(func() bool {
			return bpfCheckIfGlobalNetworkPolicyProgrammed(tc.Felixes[0], w[0].InterfaceName, "egress", "policy-test", "allow", true)
		}, "2s", "200ms").Should(BeTrue())

		Eventually(func() bool {
			return bpfCheckIfGlobalNetworkPolicyProgrammed(tc.Felixes[0], w[1].InterfaceName, "ingress", "policy-test", "allow", true)
		}, "2s", "200ms").Should(BeTrue())

		Eventually(func() bool {
			return bpfCheckIfGlobalNetworkPolicyProgrammed(tc.Felixes[0], w[1].InterfaceName, "egress", "policy-test", "allow", true)
		}, "2s", "200ms").Should(BeTrue())

		for i := 0; i < 10; i++ {
			_, err := w[1].RunCmd("pktgen", w[1].IP, w[0].IP, "udp", "--port-src", "8055", "--port-dst", "8055")
			Expect(err).NotTo(HaveOccurred())
		}

		Eventually(func() int {
			m = dumpRuleCounterMap(tc.Felixes[0])
			return len(m)
		}, "2s", "200ms").Should(Equal(2))
		for _, v := range m {
			Expect(v).To(Equal(uint64(1)))
		}

		checkRuleCounters(tc.Felixes[0], w[1].InterfaceName, "egress", "policy-test", 1)
		checkRuleCounters(tc.Felixes[0], w[0].InterfaceName, "ingress", "policy-test", 1)

		_, err := calicoClient.GlobalNetworkPolicies().Delete(context.Background(), "policy-test", options2.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())

		Eventually(func() bool {
			return bpfCheckIfGlobalNetworkPolicyProgrammed(tc.Felixes[0], w[0].InterfaceName, "ingress", "policy-test", "allow", true)
		}, "2s", "200ms").ShouldNot(BeTrue())

		Eventually(func() bool {
			return bpfCheckIfGlobalNetworkPolicyProgrammed(tc.Felixes[0], w[0].InterfaceName, "egress", "policy-test", "allow", true)
		}, "2s", "200ms").ShouldNot(BeTrue())

		Eventually(func() bool {
			return bpfCheckIfGlobalNetworkPolicyProgrammed(tc.Felixes[0], w[1].InterfaceName, "ingress", "policy-test", "allow", true)
		}, "2s", "200ms").ShouldNot(BeTrue())

		Eventually(func() bool {
			return bpfCheckIfGlobalNetworkPolicyProgrammed(tc.Felixes[0], w[1].InterfaceName, "egress", "policy-test", "allow", true)
		}, "2s", "200ms").ShouldNot(BeTrue())

		Eventually(func() int {
			m = dumpRuleCounterMap(tc.Felixes[0])
			return len(m)
		}, "5s", "200ms").Should(Equal(0))
	})
})

func dumpRuleCounterMap(felix *infrastructure.Felix) counters.PolicyMapMem {
	rcMap := counters.PolicyMap()
	m := make(counters.PolicyMapMem)
	dumpBPFMap(felix, rcMap, counters.PolicyMapMemIter(m))
	return m
}

func checkRuleCounters(felix *infrastructure.Felix, ifName, hook, polName string, count int) {
	out, err := felix.ExecOutput("calico-bpf", "policy", "dump", ifName, hook, "--asm")
	Expect(err).NotTo(HaveOccurred())
	strOut := strings.Split(out, "\n")

	startOfPol := -1
	for idx, str := range strOut {
		if strings.Contains(str, fmt.Sprintf("Start of GlobalNetworkPolicy %s", polName)) {
			startOfPol = idx
			break
		}
	}
	Expect(startOfPol).NotTo(Equal(-1))
	Expect(strings.Contains(strOut[startOfPol+2], fmt.Sprintf("count = %d", count))).To(BeTrue())
}

func checkDroppedByPolicyCounters(g Gomega, felix *infrastructure.Felix, ifName string, iCount, eCount int) {
	out, err := felix.ExecOutput("calico-bpf", "counters", "dump", fmt.Sprintf("--iface=%s", ifName))
	g.Expect(err).NotTo(HaveOccurred())
	strOut := strings.Split(out, "\n")

	f := func(c rune) bool {
		return c == '|'
	}

	var (
		iCounter, eCounter int
		xCounter           string
	)

	dropped := false

	for _, line := range strOut {
		fields := strings.FieldsFunc(line, f)
		if len(fields) < 5 {
			continue
		}

		if strings.TrimSpace(strings.ToLower(fields[0])) == "dropped" {
			dropped = true
		}

		// "Dropped by policy" is the description of DroppedByPolicy counter
		// defined in felix/bpf/counters/counters.go.
		if dropped && strings.TrimSpace(strings.ToLower(fields[1])) == "by policy" {
			iCounter, _ = strconv.Atoi(strings.TrimSpace(strings.ToLower(fields[2])))
			eCounter, _ = strconv.Atoi(strings.TrimSpace(strings.ToLower(fields[3])))
			xCounter = strings.TrimSpace(strings.ToLower(fields[4]))
			break
		}
	}
	g.Expect(xCounter).To(Equal("n/a"))
	g.Expect(eCounter).To(BeNumerically(">=", eCount))
	g.Expect(iCounter).To(BeNumerically(">=", iCount))
}
