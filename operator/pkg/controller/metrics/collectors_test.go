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

package metrics_test

import (
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/apis"
	"github.com/projectcalico/calico/operator/pkg/controller/metrics"
	ctrlrfake "github.com/projectcalico/calico/operator/pkg/ctrlruntime/client/fake"
)

func TestMetrics(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Metrics Suite")
}

var _ = Describe("OperatorCollector", func() {
	var (
		scheme *runtime.Scheme
	)

	BeforeEach(func() {
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		Expect(corev1.AddToScheme(scheme)).NotTo(HaveOccurred())
	})

	Context("component status metrics", func() {
		It("should emit metrics for TigeraStatus objects", func() {
			ts := &operatorv1.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: "calico"},
				Status: operatorv1.TigeraStatusStatus{
					Conditions: []operatorv1.TigeraStatusCondition{
						{Type: operatorv1.ComponentAvailable, Status: operatorv1.ConditionTrue},
						{Type: operatorv1.ComponentProgressing, Status: operatorv1.ConditionFalse},
						{Type: operatorv1.ComponentDegraded, Status: operatorv1.ConditionFalse},
					},
				},
			}
			cli := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(ts).Build()
			collector := metrics.NewOperatorCollector(cli)

			expected := `
# HELP tigera_operator_component_status TigeraStatus conditions for operator-managed components. 1 = true, 0 = false.
# TYPE tigera_operator_component_status gauge
tigera_operator_component_status{component="calico",condition="available"} 1
tigera_operator_component_status{component="calico",condition="progressing"} 0
tigera_operator_component_status{component="calico",condition="degraded"} 0
`
			Expect(testutil.CollectAndCompare(collector, strings.NewReader(expected),
				"tigera_operator_component_status")).NotTo(HaveOccurred())
		})

		It("should emit 0 for all conditions when status has no conditions", func() {
			ts := &operatorv1.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: "monitor"},
				Status:     operatorv1.TigeraStatusStatus{},
			}
			cli := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(ts).Build()
			collector := metrics.NewOperatorCollector(cli)

			expected := `
# HELP tigera_operator_component_status TigeraStatus conditions for operator-managed components. 1 = true, 0 = false.
# TYPE tigera_operator_component_status gauge
tigera_operator_component_status{component="monitor",condition="available"} 0
tigera_operator_component_status{component="monitor",condition="progressing"} 0
tigera_operator_component_status{component="monitor",condition="degraded"} 0
`
			Expect(testutil.CollectAndCompare(collector, strings.NewReader(expected),
				"tigera_operator_component_status")).NotTo(HaveOccurred())
		})

		It("should handle multiple TigeraStatus objects", func() {
			ts1 := &operatorv1.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: "calico"},
				Status: operatorv1.TigeraStatusStatus{
					Conditions: []operatorv1.TigeraStatusCondition{
						{Type: operatorv1.ComponentAvailable, Status: operatorv1.ConditionTrue},
						{Type: operatorv1.ComponentProgressing, Status: operatorv1.ConditionFalse},
						{Type: operatorv1.ComponentDegraded, Status: operatorv1.ConditionFalse},
					},
				},
			}
			ts2 := &operatorv1.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: "apiserver"},
				Status: operatorv1.TigeraStatusStatus{
					Conditions: []operatorv1.TigeraStatusCondition{
						{Type: operatorv1.ComponentAvailable, Status: operatorv1.ConditionFalse},
						{Type: operatorv1.ComponentProgressing, Status: operatorv1.ConditionTrue},
						{Type: operatorv1.ComponentDegraded, Status: operatorv1.ConditionTrue},
					},
				},
			}
			cli := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(ts1, ts2).Build()
			collector := metrics.NewOperatorCollector(cli)

			// Verify each component's metrics individually
			count := testutil.CollectAndCount(collector, "tigera_operator_component_status")
			Expect(count).To(Equal(6)) // 2 components * 3 conditions
		})
	})

	Context("TLS certificate expiry metrics", func() {
		It("should emit metrics for secrets with signer label and expiry annotation", func() {
			expiry := time.Date(2027, 6, 15, 12, 0, 0, 0, time.UTC)
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "manager-tls",
					Namespace: "calico-system",
					Labels: map[string]string{
						"certificates.operator.tigera.io/signer": "tigera-operator-signer",
					},
					Annotations: map[string]string{
						"certificates.operator.tigera.io/expiry": expiry.Format("2006-01-02T15:04:05Z"),
						"certificates.operator.tigera.io/issuer": "tigera-operator-signer",
					},
				},
			}
			cli := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(secret).Build()
			collector := metrics.NewOperatorCollector(cli)

			count := testutil.CollectAndCount(collector, "tigera_operator_tls_certificate_expiry_timestamp_seconds")
			Expect(count).To(Equal(1))
		})

		It("should skip secrets without signer label", func() {
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "some-secret",
					Namespace: "calico-system",
					Annotations: map[string]string{
						"certificates.operator.tigera.io/expiry": "2027-06-15T12:00:00Z",
					},
				},
			}
			cli := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(secret).Build()
			collector := metrics.NewOperatorCollector(cli)

			count := testutil.CollectAndCount(collector, "tigera_operator_tls_certificate_expiry_timestamp_seconds")
			Expect(count).To(Equal(0))
		})

		It("should skip secrets without expiry annotation", func() {
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "manager-tls",
					Namespace: "calico-system",
					Labels: map[string]string{
						"certificates.operator.tigera.io/signer": "tigera-operator-signer",
					},
				},
			}
			cli := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(secret).Build()
			collector := metrics.NewOperatorCollector(cli)

			count := testutil.CollectAndCount(collector, "tigera_operator_tls_certificate_expiry_timestamp_seconds")
			Expect(count).To(Equal(0))
		})
	})
})
