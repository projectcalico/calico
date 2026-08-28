// Copyright (c) 2024-2026 Tigera, Inc. All rights reserved.

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

package nonclusterhost_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/nonclusterhost"
)

var _ = Describe("NonClusterHost rendering tests", func() {
	var cfg *nonclusterhost.Config

	BeforeEach(func() {
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())

		cfg = &nonclusterhost.Config{
			NonClusterHost: operatorv1.NonClusterHostSpec{
				Endpoint: "https://1.2.3.4:5678",
			},
		}
	})

	It("should render NonClusterHost resources", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "tigera-noncluster-host", ns: "calico-system", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "tigera-noncluster-host", ns: "calico-system", group: "", version: "v1", kind: "Secret"},
			{name: "tigera-noncluster-host", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-noncluster-host", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
		}

		component := nonclusterhost.NonClusterHost(cfg)
		toCreate, toDelete := component.Objects()
		Expect(toCreate).To(HaveLen(len(expectedResources)))
		Expect(toDelete).To(BeNil())

		for i, expectedRes := range expectedResources {
			rtest.ExpectResourceTypeAndObjectMetadata(toCreate[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}

		secret := rtest.GetResource(toCreate, "tigera-noncluster-host", "calico-system", "", "v1", "Secret").(*corev1.Secret)
		Expect(secret.GetObjectMeta().GetAnnotations()).To(HaveKeyWithValue("kubernetes.io/service-account.name", "tigera-noncluster-host"))
		Expect(secret.Type).To(Equal(corev1.SecretType("kubernetes.io/service-account-token")))

		clusterRole := rtest.GetResource(toCreate, "tigera-noncluster-host", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(clusterRole.Rules).To(ContainElements(
			rbacv1.PolicyRule{
				APIGroups: []string{"discovery.k8s.io"},
				Resources: []string{"endpointslices"},
				Verbs:     []string{"list", "watch"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"endpoints", "services"},
				Verbs:     []string{"watch", "list", "get"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{"networking.k8s.io"},
				Resources: []string{"networkpolicies"},
				Verbs:     []string{"watch", "list"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{"policy.networking.k8s.io"},
				Resources: []string{
					"clusternetworkpolicies",
					"adminnetworkpolicies",
					"baselineadminnetworkpolicies",
				},
				Verbs: []string{"get", "watch", "list"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"pods", "namespaces", "serviceaccounts"},
				Verbs:     []string{"watch", "list"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"nodes"},
				Verbs:     []string{"get", "list", "watch"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"get"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
				Resources: []string{
					"bfdconfigurations",
					"bgpconfigurations",
					"clusterinformations",
					"egressgatewaypolicies",
					"externalnetworks",
					"felixconfigurations",
					"globalnetworkpolicies",
					"globalnetworksets",
					"hostendpoints",
					"ipamblocks",
					"ippools",
					"licensekeys",
					"networkpolicies",
					"networks",
					"networksets",
					"packetcaptures",
					"remoteclusterconfigurations",
					"stagedglobalnetworkpolicies",
					"stagedkubernetesnetworkpolicies",
					"stagednetworkpolicies",
					"tiers",
				},
				Verbs: []string{"get", "list", "watch"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"serviceaccounts/token"},
				Verbs:     []string{"create"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{"operator.tigera.io"},
				Resources: []string{"nonclusterhosts"},
				Verbs:     []string{"get", "list", "watch"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{"linseed.tigera.io"},
				Resources: []string{"flowlogs", "dnslogs", "policyactivity"},
				Verbs:     []string{"create"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{"certificates.k8s.io"},
				Resources: []string{"certificatesigningrequests"},
				Verbs:     []string{"create", "delete", "list", "watch"},
			},
			rbacv1.PolicyRule{
				APIGroups:     []string{"certificates.tigera.io"},
				Resources:     []string{"certificatesigningrequests/common-name"},
				Verbs:         []string{"create"},
				ResourceNames: []string{"typha-server-noncluster-host"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
				Resources: []string{"hostendpoints"},
				Verbs:     []string{"list", "update"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"secrets"},
				Verbs:     []string{"get"},
				ResourceNames: []string{
					"node-certs-noncluster-host",
					"typha-certs-noncluster-host",
				},
			},
		))
	})
})
