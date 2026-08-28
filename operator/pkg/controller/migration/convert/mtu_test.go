// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.

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

package convert

import (
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/migration/cni"
	v1 "k8s.io/api/core/v1"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("mtu handler", func() {
	var (
		comps = emptyComponents()
		i     = &operatorv1.Installation{}
	)

	BeforeEach(func() {
		comps = emptyComponents()
		i = &operatorv1.Installation{}
	})
	It("should not set mtu if none defined", func() {
		err := handleMTU(&comps, i)
		Expect(err).ToNot(HaveOccurred())
		Expect(i.Spec.CalicoNetwork).To(BeNil())
	})

	It("should read mtu from cni config", func() {
		comps.cni.CalicoConfig = &cni.CalicoConf{
			MTU: 1234,
		}
		err := handleMTU(&comps, i)
		Expect(err).ToNot(HaveOccurred())
		Expect(i.Spec.CalicoNetwork).ToNot(BeNil())
		Expect(*i.Spec.CalicoNetwork.MTU).To(BeEquivalentTo(1234))
	})

	DescribeTable("should read mtu from env vars on calico-node", func(env string) {
		comps.node.Spec.Template.Spec.Containers[0].Env = []v1.EnvVar{{
			Name:  env,
			Value: "1324",
		}}
		err := handleMTU(&comps, i)
		Expect(err).ToNot(HaveOccurred())
		Expect(i.Spec.CalicoNetwork).ToNot(BeNil())
		Expect(*i.Spec.CalicoNetwork.MTU).To(BeEquivalentTo(1324))
	},
		Entry("ipip", "FELIX_IPINIPMTU"),
		Entry("vxlan", "FELIX_VXLANMTU"),
		Entry("vxlanV6", "FELIX_VXLANMTUV6"),
		Entry("wireguard", "FELIX_WIREGUARDMTU"),
		Entry("wireguardV6", "FELIX_WIREGUARDMTUV6"),
	)

	It("should error if given conflicting mtu values between env vars", func() {
		comps.node.Spec.Template.Spec.Containers[0].Env = []v1.EnvVar{
			{
				Name:  "FELIX_IPINIPMTU",
				Value: "1324",
			},
			{
				Name:  "FELIX_VXLANMTU",
				Value: "999",
			},
		}
		err := handleMTU(&comps, i)
		Expect(err).To(HaveOccurred())
	})

	It("should error if given conflicting mtu values between cni and env var", func() {
		comps.node.Spec.Template.Spec.Containers[0].Env = []v1.EnvVar{{
			Name:  "FELIX_IPINIPMTU",
			Value: "1324",
		}}
		comps.cni.CalicoConfig = &cni.CalicoConf{
			MTU: 1234,
		}
		err := handleMTU(&comps, i)
		Expect(err).To(HaveOccurred())
	})
})
