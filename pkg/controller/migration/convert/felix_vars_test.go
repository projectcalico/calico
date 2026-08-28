// Copyright (c) 2022-2026 Tigera, Inc. All rights reserved.

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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kscheme "k8s.io/client-go/kubernetes/scheme"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"
	"github.com/tigera/operator/pkg/apis"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
)

var _ = Describe("felix env parser", func() {
	It("converts a string", func() {
		fe, err := patchFromVal("dataplanedriver", "foo")
		Expect(err).ToNot(HaveOccurred())
		Expect(fe).To(Equal(patch{
			Op:    "replace",
			Path:  "/spec/dataplaneDriver",
			Value: "foo",
		}))
	})

	It("converts a boolean", func() {
		t := true
		fe, err := patchFromVal("useinternaldataplanedriver", "true")
		Expect(err).ToNot(HaveOccurred())
		Expect(fe).To(Equal(patch{
			Op:    "replace",
			Path:  "/spec/useInternalDataplaneDriver",
			Value: &t,
		}))
	})

	It("converts a duration", func() {
		fe, err := patchFromVal("routerefreshinterval", "4s")
		Expect(err).ToNot(HaveOccurred())
		Expect(fe).To(Equal(patch{
			Op:    "replace",
			Path:  "/spec/routeRefreshInterval",
			Value: &metav1.Duration{Duration: 4 * time.Second},
		}))
	})

	It("converts a *uint32", func() {
		m := uint32(20)
		fe, err := patchFromVal("iptablesmarkmask", "20")
		Expect(err).ToNot(HaveOccurred())
		Expect(fe).To(Equal(patch{
			Op:    "replace",
			Path:  "/spec/iptablesMarkMask",
			Value: &m,
		}))
	})

	It("converts a slice of protoports", func() {
		fe, err := patchFromVal("failsafeinboundhostports", "tcp:10250")
		Expect(err).ToNot(HaveOccurred())
		Expect(fe).To(Equal(patch{
			Op:    "replace",
			Path:  "/spec/failsafeInboundHostPorts",
			Value: &[]v3.ProtoPort{{Port: 10250, Protocol: "tcp"}},
		}))
	})

	It("converts a RouteTableRange", func() {
		fe, err := patchFromVal("routetablerange", "22-44")
		Expect(err).ToNot(HaveOccurred())
		Expect(fe).To(Equal(patch{
			Op:    "replace",
			Path:  "/spec/routeTableRange",
			Value: &v3.RouteTableRange{Min: 22, Max: 44},
		}))
	})

	It("converts a AWSSrcDstCheckOption", func() {
		d := v3.AWSSrcDstCheckOption(v3.AWSSrcDstCheckOptionDisable)
		fe, err := patchFromVal("awssrcdstcheck", "Disable")
		Expect(err).ToNot(HaveOccurred())
		Expect(fe.Value).To(Equal(&d))
		Expect(fe).To(Equal(patch{
			Op:    "replace",
			Path:  "/spec/awsSrcDstCheck",
			Value: &d,
		}))
	})

	It("converts a *[]string", func() {
		fe, err := patchFromVal("externalnodescidrlist", "1.1.1.1,2.2.2.2")
		Expect(err).ToNot(HaveOccurred())
		Expect(fe).To(Equal(patch{
			Op:    "replace",
			Path:  "/spec/externalNodesList",
			Value: &[]string{"1.1.1.1", "2.2.2.2"},
		}))
	})

	It("converts a numorstring", func() {
		fe, err := patchFromVal("kubenodeportranges", "10250:10260")
		Expect(err).ToNot(HaveOccurred())
		Expect(fe).To(Equal(patch{
			Op:    "replace",
			Path:  "/spec/kubeNodePortRanges",
			Value: &[]numorstring.Port{{MinPort: 10250, MaxPort: 10260}},
		}))
	})

	Context("creating a felixconfiguration", func() {
		c := emptyComponents()

		BeforeEach(func() {
			c = emptyComponents()

			scheme := kscheme.Scheme
			Expect(apis.AddToScheme(scheme, false)).ToNot(HaveOccurred())
			c.client = ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(emptyFelixConfig()).Build()
		})

		It("handle empty BPF Enabled environment variable", func() {
			c.node.Spec.Template.Spec.Containers[0].Env = []v1.EnvVar{}

			Expect(handleFelixVars(&c)).ToNot(HaveOccurred())

			f := v3.FelixConfiguration{}
			Expect(c.client.Get(ctx, types.NamespacedName{Name: "default"}, &f)).ToNot(HaveOccurred())
			Expect(f.Spec.BPFEnabled).To(BeNil())
		})

		It("handles 'none' failsafe inbound ports", func() {
			c.node.Spec.Template.Spec.Containers[0].Env = []v1.EnvVar{{
				Name:  "FELIX_FAILSAFEINBOUNDHOSTPORTS",
				Value: "none",
			}}

			Expect(handleFelixVars(&c)).ToNot(HaveOccurred())

			f := v3.FelixConfiguration{}
			Expect(c.client.Get(ctx, types.NamespacedName{Name: "default"}, &f)).ToNot(HaveOccurred())
			Expect(f.Spec.FailsafeInboundHostPorts).ToNot(BeNil())
			Expect(f.Spec.FailsafeInboundHostPorts).To(Equal(&[]v3.ProtoPort{}))
		})

		It("handles 'none' failsafe outbound ports", func() {
			c.node.Spec.Template.Spec.Containers[0].Env = []v1.EnvVar{{
				Name:  "FELIX_FAILSAFEOUTBOUNDHOSTPORTS",
				Value: "none",
			}}

			Expect(handleFelixVars(&c)).ToNot(HaveOccurred())

			f := v3.FelixConfiguration{}
			Expect(c.client.Get(ctx, types.NamespacedName{Name: "default"}, &f)).ToNot(HaveOccurred())
			Expect(f.Spec.FailsafeOutboundHostPorts).ToNot(BeNil())
			Expect(f.Spec.FailsafeOutboundHostPorts).To(Equal(&[]v3.ProtoPort{}))
		})

		It("handles natPortRange", func() {
			c.node.Spec.Template.Spec.Containers[0].Env = []v1.EnvVar{{
				Name:  "FELIX_NATPORTRANGE",
				Value: "32768:65535",
			}}

			Expect(handleFelixVars(&c)).ToNot(HaveOccurred())

			f := v3.FelixConfiguration{}
			Expect(c.client.Get(ctx, types.NamespacedName{Name: "default"}, &f)).ToNot(HaveOccurred())
			Expect(f.Spec.NATPortRange).ToNot(BeNil())
			Expect(f.Spec.NATPortRange).To(Equal(&numorstring.Port{MinPort: 32768, MaxPort: 65535}))
		})

		It("sets a duration", func() {
			c.node.Spec.Template.Spec.Containers[0].Env = []v1.EnvVar{{
				Name:  "FELIX_IPTABLESREFRESHINTERVAL",
				Value: "20",
			}}

			Expect(handleFelixVars(&c)).ToNot(HaveOccurred())

			f := v3.FelixConfiguration{}
			Expect(c.client.Get(ctx, types.NamespacedName{Name: "default"}, &f)).ToNot(HaveOccurred())
			Expect(f.Spec.IptablesRefreshInterval).ToNot(BeNil())
			Expect(f.Spec.IptablesRefreshInterval).To(Equal(&metav1.Duration{Duration: 20 * time.Second}))
		})

		It("sets iptablesbackend", func() {
			c.node.Spec.Template.Spec.Containers[0].Env = []v1.EnvVar{{
				Name:  "FELIX_IPTABLESBACKEND",
				Value: "Legacy",
			}}

			Expect(handleFelixVars(&c)).ToNot(HaveOccurred())

			f := v3.FelixConfiguration{}
			Expect(c.client.Get(ctx, types.NamespacedName{Name: "default"}, &f)).ToNot(HaveOccurred())
			Expect(f.Spec.IptablesBackend).ToNot(BeNil())
			legacy := v3.IptablesBackend(v3.IptablesBackendLegacy)
			Expect(f.Spec.IptablesBackend).To(Equal(&legacy))
		})
	})
})
