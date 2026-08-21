// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package networkpolicy_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/tigera/api/pkg/lib/numorstring"

	"github.com/tigera/operator/pkg/render/common/networkpolicy"
)

func TestNetworkPolicy(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "pkg/render/common/networkpolicy Suite")
}

var _ = Describe("egress destination rules", func() {
	port := func(p uint16) numorstring.Port { return numorstring.SinglePort(p) }

	DescribeTable("ClusterServiceWithDomain",
		func(host, clusterDomain string, wantNS, wantName string, wantOK bool) {
			ns, name, ok := networkpolicy.ClusterServiceWithDomain(host, clusterDomain)
			Expect(ok).To(Equal(wantOK), "match result for %q", host)
			Expect(ns).To(Equal(wantNS))
			Expect(name).To(Equal(wantName))
		},
		Entry("bare .svc", "lgtm.otel-demo.svc", "", "otel-demo", "lgtm", true),
		Entry("bare .svc with a trailing dot", "lgtm.otel-demo.svc.", "", "otel-demo", "lgtm", true),
		Entry("with the cluster domain", "lgtm.otel-demo.svc.cluster.local", "cluster.local", "otel-demo", "lgtm", true),
		Entry("with the cluster domain and a trailing dot", "lgtm.otel-demo.svc.cluster.local.", "cluster.local", "otel-demo", "lgtm", true),
		Entry("external host containing an svc label", "proxy.corp.svc.example.com", "cluster.local", "", "", false),
		Entry("external host containing an svc label, no cluster domain", "proxy.corp.svc.example.com", "", "", "", false),
		Entry("a plain hostname", "otlp.example.com", "cluster.local", "", "", false),
		Entry("a literal IP", "10.1.2.3", "cluster.local", "", "", false),
		Entry("too few labels", "otel-demo.svc", "cluster.local", "", "", false),
	)

	Describe("EntityRuleForHostPort", func() {
		It("pins a literal IPv4 to an exact net", func() {
			r := networkpolicy.EntityRuleForHostPort("10.1.2.3", "cluster.local", port(4317))
			Expect(r.Nets).To(Equal([]string{"10.1.2.3/32"}))
			Expect(r.Ports).To(Equal([]numorstring.Port{port(4317)}))
		})

		It("pins a literal IPv6 to an exact net", func() {
			r := networkpolicy.EntityRuleForHostPort("2001:db8::1", "cluster.local", port(4317))
			Expect(r.Nets).To(Equal([]string{"2001:db8::1/128"}))
		})

		It("matches an in-cluster Service by service, carrying no ports", func() {
			// Calico rejects a rule that sets both a service selector and ports.
			r := networkpolicy.EntityRuleForHostPort("lgtm.otel-demo.svc.cluster.local", "cluster.local", port(4317))
			Expect(r.Services).NotTo(BeNil())
			Expect(r.Services.Name).To(Equal("lgtm"))
			Expect(r.Services.Namespace).To(Equal("otel-demo"))
			Expect(r.Ports).To(BeEmpty())
		})

		It("falls back to the domain for an external hostname", func() {
			r := networkpolicy.EntityRuleForHostPort("otlp.example.com", "cluster.local", port(443))
			Expect(r.Domains).To(Equal([]string{"otlp.example.com"}))
			Expect(r.Ports).To(Equal([]numorstring.Port{port(443)}))
		})

		It("never returns a rule that constrains only the port", func() {
			for _, host := range []string{"otlp.example.com", "10.1.2.3", "lgtm.otel-demo.svc"} {
				r := networkpolicy.EntityRuleForHostPort(host, "cluster.local", port(443))
				Expect(r.Services != nil || len(r.Nets) > 0 || len(r.Domains) > 0).To(BeTrue(),
					"rule for %q constrains only the port", host)
			}
		})
	})

	Describe("ParseHostPort", func() {
		It("splits a host:port destination", func() {
			host, p, err := networkpolicy.ParseHostPort("mgmt.example.com:9449")
			Expect(err).NotTo(HaveOccurred())
			Expect(host).To(Equal("mgmt.example.com"))
			Expect(p).To(Equal(port(9449)))
		})

		It("rejects a URL rather than defaulting the port from its scheme", func() {
			_, _, err := networkpolicy.ParseHostPort("https://mgmt.example.com")
			Expect(err).To(HaveOccurred())
		})

		It("rejects a bare host", func() {
			_, _, err := networkpolicy.ParseHostPort("mgmt.example.com")
			Expect(err).To(HaveOccurred())
		})
	})
})
