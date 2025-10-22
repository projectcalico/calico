// Copyright (c) 2023 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
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

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/metrics"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ label index metrics tests", []apiconfig.DatastoreType{apiconfig.Kubernetes, apiconfig.EtcdV3}, func(getInfra infrastructure.InfraFactory) {
	var (
		tc     infrastructure.TopologyContainers
		infra  infrastructure.DatastoreInfra
		client client.Interface
		w      [2]*workload.Workload
	)

	BeforeEach(func() {
		infra = getInfra()
		opts := infrastructure.DefaultTopologyOptions()
		opts.ExtraEnvVars["FELIX_PROMETHEUSMETRICSENABLED"] = "true"
		opts.ExtraEnvVars["FELIX_PROMETHEUSMETRICSHOST"] = "0.0.0.0"
		tc, client = infrastructure.StartNNodeTopology(1, opts, infra)

		for i := range w {
			w[i] = workload.Run(
				tc.Felixes[0],
				"w",
				"default",
				"10.65.0.1",
				"8080",
				"tcp",
			)
			w[i].WorkloadEndpoint.Labels["common"] = "x"
			w[i].WorkloadEndpoint.Labels["foo"] = fmt.Sprint(i)
		}
		w[1].WorkloadEndpoint.Namespace = "another"
	})

	It("should report expected prometheus stats with various policies", func() {
		By("Reporting 0 at start of day")
		Eventually(metrics.GetFelixMetricIntFn(tc.Felixes[0].IP, "felix_label_index_num_endpoints")).Should(BeNumerically("==", 0))
		Expect(metrics.GetFelixMetricInt(tc.Felixes[0].IP, "felix_label_index_selector_evals{result=\"false\"}")).To(BeNumerically("==", 0))
		Expect(metrics.GetFelixMetricInt(tc.Felixes[0].IP, "felix_label_index_selector_evals{result=\"true\"}")).To(BeNumerically("==", 0))
		Expect(metrics.GetFelixMetricInt(tc.Felixes[0].IP, "felix_label_index_num_active_selectors{optimized=\"false\"}")).To(BeNumerically("==", 0))
		Expect(metrics.GetFelixMetricInt(tc.Felixes[0].IP, "felix_label_index_num_active_selectors{optimized=\"true\"}")).To(BeNumerically("==", 0))

		By("responding to an endpoint")
		w[0].ConfigureInInfra(infra)
		Eventually(metrics.GetFelixMetricIntFn(tc.Felixes[0].IP, "felix_label_index_num_endpoints")).Should(BeNumerically("==", 1))

		By("responding to a second endpoint")
		w[1].ConfigureInInfra(infra)
		Eventually(metrics.GetFelixMetricIntFn(tc.Felixes[0].IP, "felix_label_index_num_endpoints")).Should(BeNumerically("==", 2))

		// Create a policy with a selector.
		By("responding to a selector")
		pol := v3.NewGlobalNetworkPolicy()
		pol.Name = "test"
		pol.Spec.Selector = "all()"
		pol.Spec.Ingress = []v3.Rule{
			{
				Action: "Allow",
				Source: v3.EntityRule{
					Selector: "foo == '0'",
				},
			},
		}
		pol, err := client.GlobalNetworkPolicies().Create(context.TODO(), pol, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		Eventually(metrics.GetFelixMetricIntFn(tc.Felixes[0].IP, "felix_label_index_strategy_evals{strategy=\"endpoint-single-value\"}")).Should(BeNumerically("==", 1))
		Expect(metrics.GetFelixMetricInt(tc.Felixes[0].IP, "felix_label_index_selector_evals{result=\"true\"}")).To(BeNumerically(">", 0))
		Expect(metrics.GetFelixMetricInt(tc.Felixes[0].IP, "felix_label_index_selector_evals{result=\"false\"}")).To(BeNumerically("==", 0))
		Expect(metrics.GetFelixMetricInt(tc.Felixes[0].IP, "felix_label_index_num_active_selectors{optimized=\"false\"}")).To(BeNumerically("==", 0))
		Expect(metrics.GetFelixMetricInt(tc.Felixes[0].IP, "felix_label_index_num_active_selectors{optimized=\"true\"}")).To(BeNumerically("==", 1))

		By("responding to an unoptimized selector")
		pol2 := v3.NewGlobalNetworkPolicy()
		pol2.Name = "test2"
		pol2.Spec.Selector = "all()"
		pol2.Spec.Ingress = []v3.Rule{
			{
				Action: "Allow",
				Source: v3.EntityRule{
					Selector: "bar == 'biff' || foo == '1'",
				},
			},
		}
		pol2, err = client.GlobalNetworkPolicies().Create(context.TODO(), pol2, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		Eventually(metrics.GetFelixMetricIntFn(tc.Felixes[0].IP, "felix_label_index_strategy_evals{strategy=\"endpoint-single-value\"}")).Should(BeNumerically("==", 1))
		Eventually(metrics.GetFelixMetricIntFn(tc.Felixes[0].IP, "felix_label_index_strategy_evals{strategy=\"endpoint-full-scan\"}")).Should(BeNumerically("==", 1))
		Expect(metrics.GetFelixMetricInt(tc.Felixes[0].IP, "felix_label_index_selector_evals{result=\"false\"}")).To(BeNumerically(">", 0))
		Expect(metrics.GetFelixMetricInt(tc.Felixes[0].IP, "felix_label_index_num_active_selectors{optimized=\"false\"}")).To(BeNumerically("==", 1))
		Expect(metrics.GetFelixMetricInt(tc.Felixes[0].IP, "felix_label_index_num_active_selectors{optimized=\"true\"}")).To(BeNumerically("==", 1))

		if _, ok := infra.(*infrastructure.EtcdDatastoreInfra); ok {
			// etcd infra doesn't create realistic enough namespaces.
			return
		}

		By("responding to a namespace selector")
		pol3 := v3.NewGlobalNetworkPolicy()
		pol3.Name = "test3"
		pol3.Spec.Selector = "all()"
		pol3.Spec.Ingress = []v3.Rule{
			{
				Action: "Allow",
				Source: v3.EntityRule{
					NamespaceSelector: "projectcalico.org/name == 'another'",
					Selector:          "common == 'x'",
				},
			},
		}
		pol3, err = client.GlobalNetworkPolicies().Create(context.TODO(), pol3, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		Eventually(metrics.GetFelixMetricIntFn(tc.Felixes[0].IP, "felix_label_index_strategy_evals{strategy=\"parent-single-value\"}")).Should(BeNumerically("==", 1),
			"Expected namespace selector with a less useful endpoint selector to result in a parent scan.")
		Expect(metrics.GetFelixMetricInt(tc.Felixes[0].IP, "felix_label_index_num_active_selectors{optimized=\"false\"}")).To(BeNumerically("==", 1))
		Expect(metrics.GetFelixMetricInt(tc.Felixes[0].IP, "felix_label_index_num_active_selectors{optimized=\"true\"}")).To(BeNumerically("==", 2))
	})

	AfterEach(func() {
		tc.Stop()
		if CurrentGinkgoTestDescription().Failed {
			infra.DumpErrorData()
		}
		infra.Stop()
	})
})
