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

package tiers_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/render"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/logstorage/eck"
	"github.com/tigera/operator/pkg/render/logstorage/kibana"
	"github.com/tigera/operator/pkg/render/testutils"
	"github.com/tigera/operator/pkg/render/tiers"
	"k8s.io/apimachinery/pkg/types"
)

var _ = Describe("Tiers rendering tests", func() {
	var cfg *tiers.Config

	clusterDNSPolicy := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/dns.json")
	clusterDNSPolicyForOCP := testutils.GetExpectedPolicyFromFile("../testutils/expected_policies/dns_ocp.json")
	nodeLocalDNSPolicyIPv4 := testutils.GetExpectedGlobalPolicyFromFile("../testutils/expected_policies/node_local_dns_ipv4.json")
	nodeLocalDNSPolicyIPv6 := testutils.GetExpectedGlobalPolicyFromFile("../testutils/expected_policies/node_local_dns_ipv6.json")
	nodeLocalDNSPolicyDual := testutils.GetExpectedGlobalPolicyFromFile("../testutils/expected_policies/node_local_dns_dual.json")

	getDNSEgressCIDRs := func(ipMode testutils.IPMode) tiers.DNSEgressCIDR {
		switch ipMode {
		case testutils.IPV4:
			return tiers.DNSEgressCIDR{
				IPV4: []string{"10.96.0.10/32"},
			}

		case testutils.IPV6:
			return tiers.DNSEgressCIDR{
				IPV6: []string{"2002:a60:a::"},
			}
		case testutils.DualStack:
			return tiers.DNSEgressCIDR{
				IPV4: []string{"10.96.0.10/32"},
				IPV6: []string{"2002:a60:a::"},
			}
		// default to IPV4 if ipMode is not set.
		default:
			return tiers.DNSEgressCIDR{
				IPV4: []string{"10.96.0.10/32"},
			}
		}
	}

	BeforeEach(func() {
		// Establish default config for test cases to override.
		cfg = &tiers.Config{
			OpenShift:      false,
			DNSEgressCIDRs: getDNSEgressCIDRs(testutils.IPV4),
			CalicoNamespaces: []string{
				common.CalicoNamespace,
				render.DexNamespace,
				render.ElasticsearchNamespace,
				render.IntrusionDetectionNamespace,
				kibana.Namespace,
				eck.OperatorNamespace,
				render.PacketCaptureNamespace,
				common.TigeraPrometheusNamespace,
				"tigera-skraper",
			},
		}
	})

	Context("calico-system rendering", func() {
		policyNames := []types.NamespacedName{
			{Name: "calico-system.cluster-dns", Namespace: "kube-system"},
			{Name: "calico-system.cluster-dns", Namespace: "openshift-dns"},
		}

		getExpectedPolicy := func(name types.NamespacedName, scenario testutils.CalicoSystemScenario) *v3.NetworkPolicy {
			if name.Name == "calico-system.cluster-dns" &&
				((scenario.OpenShift && name.Namespace == "openshift-dns") || (!scenario.OpenShift && name.Namespace == "kube-system")) {
				return testutils.SelectPolicyByProvider(scenario, clusterDNSPolicy, clusterDNSPolicyForOCP)
			}

			return nil
		}

		DescribeTable("should render calico-system network policy",
			func(scenario testutils.CalicoSystemScenario) {
				cfg.OpenShift = scenario.OpenShift

				component := tiers.Tiers(cfg)
				resourcesToCreate, _ := component.Objects()

				// Validate tier render
				calicoSystem := rtest.GetResource(resourcesToCreate, "calico-system", "", "projectcalico.org", "v3", "Tier").(*v3.Tier)
				Expect(*calicoSystem.Spec.Order).To(Equal(100.0))

				// Validate created policy render
				for _, policyName := range policyNames {
					policy := testutils.GetCalicoSystemPolicyFromResources(policyName, resourcesToCreate)
					expectedPolicy := getExpectedPolicy(policyName, scenario)
					Expect(policy).To(Equal(expectedPolicy))
				}
			},

			Entry("for management/standalone, kube-dns", testutils.CalicoSystemScenario{ManagedCluster: false, OpenShift: false}),
			Entry("for management/standalone, openshift-dns", testutils.CalicoSystemScenario{ManagedCluster: false, OpenShift: true}),
			Entry("for managed, kube-dns", testutils.CalicoSystemScenario{ManagedCluster: true, OpenShift: false}),
			Entry("for managed, openshift-dns", testutils.CalicoSystemScenario{ManagedCluster: true, OpenShift: true}),
		)
	})

	Context("calico-system node-local-dns global policy rendering", func() {
		globalPolicyNames := []string{
			"calico-system.node-local-dns",
		}

		getExpectedPolicy := func(ipMode testutils.IPMode) *v3.GlobalNetworkPolicy {
			switch ipMode {
			case testutils.IPV4:
				return nodeLocalDNSPolicyIPv4
			case testutils.IPV6:
				return nodeLocalDNSPolicyIPv6
			case testutils.DualStack:
				return nodeLocalDNSPolicyDual
			// default behaviour is IPV4
			default:
				return nodeLocalDNSPolicyIPv4
			}
		}

		DescribeTable("should render for single and dual stack",
			func(ipMode testutils.IPMode) {
				cfg.DNSEgressCIDRs = getDNSEgressCIDRs(ipMode)
				component := tiers.Tiers(cfg)
				resourcesToCreate, _ := component.Objects()

				// Validate tier render
				calicoSystem := rtest.GetGlobalResource(resourcesToCreate, "calico-system", "projectcalico.org", "v3", "Tier").(*v3.Tier)
				Expect(*calicoSystem.Spec.Order).To(Equal(100.0))

				// Validate created policy render
				for _, policyName := range globalPolicyNames {
					policy := testutils.GetCalicoSystemGlobalPolicyFromResources(policyName, resourcesToCreate)
					expectedPolicy := getExpectedPolicy(ipMode)
					Expect(policy).To(Equal(expectedPolicy))
				}
			},

			Entry("for IPV4", testutils.IPV4),
			Entry("for IPV6", testutils.IPV6),
			Entry("for DualStack", testutils.DualStack),
			Entry("for when ipMode is not provided", nil),
		)
	})
})
