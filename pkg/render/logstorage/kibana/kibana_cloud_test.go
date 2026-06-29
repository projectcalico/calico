// Copyright (c) 2024-2026 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package kibana_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	kbv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/kibana/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/logstorage/kibana"
)

var _ = Describe("Kibana cloud rendering tests", func() {
	// CloudKibanaConfigOverrides is a package-global populated only by the cloud-gated controller.
	// Reset it after each test so a leaked value cannot affect the non-cloud kibana specs.
	AfterEach(func() {
		kibana.CloudKibanaConfigOverrides = map[string]interface{}{}
	})

	Context("single-tenant rendering with internal elastic", func() {
		var installation *operatorv1.InstallationSpec
		var replicas int32
		var cfg *kibana.Configuration

		expectedResources := []client.Object{
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: kibana.Namespace}},
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: kibana.PolicyName, Namespace: kibana.Namespace}},
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: networkpolicy.CalicoComponentDefaultDenyPolicyName, Namespace: kibana.Namespace}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "tigera-kibana", Namespace: kibana.Namespace}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret", Namespace: kibana.Namespace}},
			&kbv1.Kibana{ObjectMeta: metav1.ObjectMeta{Name: kibana.CRName, Namespace: kibana.Namespace}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraOperatorSecrets, Namespace: kibana.Namespace}},
		}

		BeforeEach(func() {
			logStorage := &operatorv1.LogStorage{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tigera-secure",
				},
				Spec: operatorv1.LogStorageSpec{
					Nodes: &operatorv1.Nodes{
						Count:                1,
						ResourceRequirements: nil,
					},
				},
				Status: operatorv1.LogStorageStatus{
					State: "",
				},
			}

			installation = &operatorv1.InstallationSpec{
				ControlPlaneReplicas: &replicas,
				KubernetesProvider:   operatorv1.ProviderNone,
				Registry:             "testregistry.com/",
			}

			replicas = 2
			kibanaKeyPair, bundle := getX509Certs(installation)

			cfg = &kibana.Configuration{
				LogStorage:    logStorage,
				Installation:  installation,
				KibanaKeyPair: kibanaKeyPair,
				PullSecrets: []*corev1.Secret{
					{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret"}},
				},
				Provider:      operatorv1.ProviderNone,
				ClusterDomain: dns.DefaultClusterDomain,
				TrustedBundle: bundle,
				Enabled:       true,
			}
		})

		It("should apply the cloud Kibana config overrides", func() {
			googleTagManagerConfig := map[string]interface{}{
				"enabled":   true,
				"container": "XYZ",
			}
			tigeraConfig := map[string]interface{}{
				"enabled":        true,
				"licenseEdition": "cloudEdition",
			}
			kibana.CloudKibanaConfigOverrides = map[string]interface{}{
				"googletagmanager": googleTagManagerConfig,
				"tigera":           tigeraConfig,
			}
			component := kibana.Kibana(cfg)
			createResources, _ := component.Objects()
			rtest.ExpectResources(createResources, expectedResources)

			kb := rtest.GetResource(createResources, kibana.CRName, kibana.Namespace, "kibana.k8s.elastic.co", "v1", "Kibana")
			Expect(kb).NotTo(BeNil())
			kibanaCR := kb.(*kbv1.Kibana)

			Expect(kibanaCR.Spec.Config.Data["googletagmanager"]).To(Equal(googleTagManagerConfig))
			Expect(kibanaCR.Spec.Config.Data["tigera"]).To(Equal(tigeraConfig))
		})

		It("should not include the googletagmanager override key when no overrides are set", func() {
			// googletagmanager is a cloud-only key not present in the default Kibana config, so it's a
			// safe signal that the cloud overrides were not applied.
			component := kibana.Kibana(cfg)
			createResources, _ := component.Objects()
			kb := rtest.GetResource(createResources, kibana.CRName, kibana.Namespace, "kibana.k8s.elastic.co", "v1", "Kibana").(*kbv1.Kibana)
			Expect(kb.Spec.Config.Data).NotTo(HaveKey("googletagmanager"))
		})
	})
})
