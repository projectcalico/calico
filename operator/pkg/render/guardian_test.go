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

package render_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/render"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/testutils"
)

// guardianObjects renders the base guardian component. The enterprise modifier is
// exercised in the pkg/enterprise/guardian tests; these tests cover the OSS render
// path, which never runs the modifier.
func guardianObjects(cfg *render.GuardianConfiguration) []client.Object {
	g := render.Guardian(cfg)
	ExpectWithOffset(1, g.ResolveImages(nil)).To(BeNil())
	objs, _ := g.Objects()
	return objs
}

func newGuardianConfig(addr string) *render.GuardianConfiguration {
	secret := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      render.GuardianSecretName,
			Namespace: common.OperatorNamespace(),
		},
		Data: map[string][]byte{
			"cert": []byte("foo"),
			"key":  []byte("bar"),
		},
	}
	scheme := runtime.NewScheme()
	Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
	cli := ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

	certificateManager, err := certificatemanager.Create(cli, nil, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
	Expect(err).NotTo(HaveOccurred())

	return &render.GuardianConfiguration{
		URL:                         addr,
		Installation:                &operatorv1.InstallationSpec{Registry: "my-reg/"},
		TunnelSecret:                secret,
		TrustedCertBundle:           certificateManager.CreateTrustedBundle(),
		ManagementClusterConnection: &operatorv1.ManagementClusterConnection{},
		IncludeEgressNetworkPolicy:  true,
	}
}

var _ = Describe("Guardian OSS rendering tests", func() {
	Context("GuardianPolicy component", func() {
		It("should render OSS network policy regardless of IncludeEgressNetworkPolicy flag", func() {
			// OSS variant should always render a network policy, even when IncludeEgressNetworkPolicy is false
			cfg := newGuardianConfig("127.0.0.1:1234")
			cfg.Installation.Variant = operatorv1.Calico
			cfg.IncludeEgressNetworkPolicy = false
			g, err := render.GuardianPolicy(cfg)
			Expect(err).NotTo(HaveOccurred())
			resources, _ := g.Objects()

			policyName := types.NamespacedName{Name: "calico-system.guardian-access", Namespace: "calico-system"}
			policy := testutils.GetCalicoSystemPolicyFromResources(policyName, resources)
			Expect(policy).NotTo(BeNil(), "OSS variant should always render a network policy")

			// The OSS policy has both Ingress and Egress, ending in a Pass so the
			// tunnel to the management cluster isn't dropped by the default-deny.
			Expect(policy.Spec.Types).To(ConsistOf(v3.PolicyTypeIngress, v3.PolicyTypeEgress))
			Expect(policy.Spec.Egress).NotTo(BeEmpty())
			Expect(policy.Spec.Egress[len(policy.Spec.Egress)-1].Action).To(Equal(v3.Pass))

			// OSS can't express domain-based egress rules.
			for _, rule := range policy.Spec.Egress {
				Expect(rule.Destination.Domains).To(BeEmpty())
			}
		})
	})
})

var _ = Describe("guardian", func() {
	Context("with public CA", func() {
		var cfg *render.GuardianConfiguration
		BeforeEach(func() {
			scheme := runtime.NewScheme()
			Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
			cli := ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

			certificateManager, err := certificatemanager.Create(cli, nil, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
			Expect(err).NotTo(HaveOccurred())

			cfg = &render.GuardianConfiguration{
				PullSecrets:       []*corev1.Secret{},
				Installation:      &operatorv1.InstallationSpec{},
				TunnelSecret:      &corev1.Secret{},
				TrustedCertBundle: certificateManager.CreateTrustedBundle(),
			}
		})
		It("should render when disabled", func() {
			resources := guardianObjects(cfg)
			Expect(resources).ToNot(BeNil())

			deployment := rtest.GetResource(resources, render.GuardianDeploymentName, render.GuardianNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			container := rtest.GetContainer(deployment.Spec.Template.Spec.Containers, "tigera-guardian")
			rtest.ExpectEnv(container.Env, "GUARDIAN_VOLTRON_CA_TYPE", "")
		})

		It("should render when set to disabled", func() {
			cfg.TunnelCAType = operatorv1.CATypeTigera
			resources := guardianObjects(cfg)
			Expect(resources).ToNot(BeNil())

			deployment := rtest.GetResource(resources, render.GuardianDeploymentName, render.GuardianNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			container := rtest.GetContainer(deployment.Spec.Template.Spec.Containers, "tigera-guardian")
			rtest.ExpectEnv(container.Env, "GUARDIAN_VOLTRON_CA_TYPE", "Tigera")
		})

		It("should render when enabled", func() {
			cfg.TunnelCAType = operatorv1.CATypePublic

			resources := guardianObjects(cfg)
			Expect(resources).ToNot(BeNil())

			deployment := rtest.GetResource(resources, render.GuardianDeploymentName, render.GuardianNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			container := rtest.GetContainer(deployment.Spec.Template.Spec.Containers, "tigera-guardian")
			rtest.ExpectEnv(container.Env, "GUARDIAN_VOLTRON_CA_TYPE", "Public")
		})
		It("should render guardian with resource requests and limits when configured", func() {
			guardianResources := corev1.ResourceRequirements{
				Limits: corev1.ResourceList{
					"cpu":     resource.MustParse("2"),
					"memory":  resource.MustParse("300Mi"),
					"storage": resource.MustParse("20Gi"),
				},
				Requests: corev1.ResourceList{
					"cpu":     resource.MustParse("1"),
					"memory":  resource.MustParse("150Mi"),
					"storage": resource.MustParse("10Gi"),
				},
			}

			cfg.ManagementClusterConnection = &operatorv1.ManagementClusterConnection{
				Spec: operatorv1.ManagementClusterConnectionSpec{
					GuardianDeployment: &operatorv1.GuardianDeployment{
						Spec: &operatorv1.GuardianDeploymentSpec{
							Template: &operatorv1.GuardianDeploymentPodTemplateSpec{
								Spec: &operatorv1.GuardianDeploymentPodSpec{
									Containers: []operatorv1.GuardianDeploymentContainer{{
										Name:      "tigera-guardian",
										Resources: &guardianResources,
									}},
								},
							},
						},
					},
				},
			}

			resources := guardianObjects(cfg)
			Expect(resources).ToNot(BeNil())

			deployment, ok := rtest.GetResource(resources, render.GuardianDeploymentName, render.GuardianNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue())
			container := rtest.GetContainer(deployment.Spec.Template.Spec.Containers, "tigera-guardian")
			Expect(deployment.Spec.Template.Spec.Containers).To(HaveLen(1))

			Expect(container).NotTo(BeNil())
			Expect(container.Resources).To(Equal(guardianResources))
		})
	})
})
