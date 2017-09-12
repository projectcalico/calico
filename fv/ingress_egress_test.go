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
	"strconv"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/felix/fv/containers"
	"github.com/projectcalico/felix/fv/utils"
	"github.com/projectcalico/felix/fv/workload"
	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/client"
)

var _ = Context("with initialized Felix, etcd datastore, 3 workloads", func() {

	var (
		etcd   *containers.Container
		felix  *containers.Container
		client *client.Client
		w      [3]*workload.Workload
	)

	BeforeEach(func() {

		etcd = RunEtcd()

		felix = RunFelix(etcd.IP)

		client = GetEtcdClient(etcd.IP)
		err := client.EnsureInitialized()
		Expect(err).NotTo(HaveOccurred())

		felixNode := api.NewNode()
		felixNode.Metadata.Name = felix.Hostname
		_, err = client.Nodes().Create(felixNode)
		Expect(err).NotTo(HaveOccurred())

		// Install a default profile that allows workloads with this profile to talk to each
		// other, in the absence of any Policy.
		defaultProfile := api.NewProfile()
		defaultProfile.Metadata.Name = "default"
		defaultProfile.Metadata.Tags = []string{"default"}
		defaultProfile.Spec.EgressRules = []api.Rule{{Action: "allow"}}
		defaultProfile.Spec.IngressRules = []api.Rule{{
			Action: "allow",
			Source: api.EntityRule{Tag: "default"},
		}}
		_, err = client.Profiles().Create(defaultProfile)
		Expect(err).NotTo(HaveOccurred())

		// Create three workloads, using that profile.
		for ii := 0; ii < 3; ii++ {
			iiStr := strconv.Itoa(ii)
			w[ii] = workload.Run(felix, "cali1"+iiStr, "10.65.0.1"+iiStr, "8055")
			w[ii].Configure(client)
		}
	})

	AfterEach(func() {

		if CurrentGinkgoTestDescription().Failed {
			utils.Run("docker", "logs", felix.Name)
			utils.Run("docker", "exec", felix.Name, "iptables-save", "-c")
			utils.Run("docker", "exec", felix.Name, "ip", "r")
		}

		for ii := 0; ii < 3; ii++ {
			w[ii].Stop()
		}
		felix.Stop()

		if CurrentGinkgoTestDescription().Failed {
			utils.Run("docker", "exec", etcd.Name, "etcdctl", "ls", "--recursive", "/")
		}
		etcd.Stop()
	})

	It("full connectivity to and from workload 0", func() {
		Expect(w[1].CanConnectTo(w[0].IP, w[0].Port)).To(BeTrue())
		Expect(w[2].CanConnectTo(w[0].IP, w[0].Port)).To(BeTrue())
		Expect(w[0].CanConnectTo(w[1].IP, w[1].Port)).To(BeTrue())
		Expect(w[0].CanConnectTo(w[2].IP, w[2].Port)).To(BeTrue())
	})

	Context("with ingress-only restriction for workload 0", func() {

		BeforeEach(func() {
			policy := api.NewPolicy()
			policy.Metadata.Name = "policy-1"
			allowFromW1 := api.Rule{
				Action: "allow",
				Source: api.EntityRule{
					Selector: "name=='" + w[1].Name + "'",
				},
			}
			policy.Spec.IngressRules = []api.Rule{allowFromW1}
			policy.Spec.Selector = "name=='" + w[0].Name + "'"
			_, err := client.Policies().Create(policy)
			Expect(err).NotTo(HaveOccurred())
		})

		It("only w1 can connect into w0, but egress from w0 is unrestricted", func() {
			Expect(w[1].CanConnectTo(w[0].IP, w[0].Port)).To(BeTrue())
			Expect(w[2].CanConnectTo(w[0].IP, w[0].Port)).To(BeFalse())
			Expect(w[0].CanConnectTo(w[1].IP, w[1].Port)).To(BeTrue())
			Expect(w[0].CanConnectTo(w[2].IP, w[2].Port)).To(BeTrue())
		})
	})

	Context("with egress-only restriction for workload 0", func() {

		BeforeEach(func() {
			policy := api.NewPolicy()
			policy.Metadata.Name = "policy-1"
			allowToW1 := api.Rule{
				Action: "allow",
				Destination: api.EntityRule{
					Selector: "name=='" + w[1].Name + "'",
				},
			}
			policy.Spec.EgressRules = []api.Rule{allowToW1}
			policy.Spec.Selector = "name=='" + w[0].Name + "'"
			_, err := client.Policies().Create(policy)
			Expect(err).NotTo(HaveOccurred())
		})

		It("ingress to w0 is unrestricted, but w0 can only connect out to w1", func() {
			Expect(w[1].CanConnectTo(w[0].IP, w[0].Port)).To(BeTrue())
			Expect(w[2].CanConnectTo(w[0].IP, w[0].Port)).To(BeTrue())
			Expect(w[0].CanConnectTo(w[1].IP, w[1].Port)).To(BeTrue())
			Expect(w[0].CanConnectTo(w[2].IP, w[2].Port)).To(BeFalse())
		})
	})

	Context("with ingress rules and types [ingress,egress]", func() {

		BeforeEach(func() {
			policy := api.NewPolicy()
			policy.Metadata.Name = "policy-1"
			allowFromW1 := api.Rule{
				Action: "allow",
				Source: api.EntityRule{
					Selector: "name=='" + w[1].Name + "'",
				},
			}
			policy.Spec.IngressRules = []api.Rule{allowFromW1}
			policy.Spec.Selector = "name=='" + w[0].Name + "'"
			policy.Spec.Types = []api.PolicyType{api.PolicyTypeIngress, api.PolicyTypeEgress}
			_, err := client.Policies().Create(policy)
			Expect(err).NotTo(HaveOccurred())
		})

		It("only w1 can connect into w0, and all egress from w0 is denied", func() {
			Expect(w[1].CanConnectTo(w[0].IP, w[0].Port)).To(BeTrue())
			Expect(w[2].CanConnectTo(w[0].IP, w[0].Port)).To(BeFalse())
			Expect(w[0].CanConnectTo(w[1].IP, w[1].Port)).To(BeFalse())
			Expect(w[0].CanConnectTo(w[2].IP, w[2].Port)).To(BeFalse())
		})
	})
})
