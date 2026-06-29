// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.

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

package render_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render"
	rtest "github.com/tigera/operator/pkg/render/common/test"
)

var _ = Describe("Tigera Secure Cloud Manager rendering tests", func() {
	installation := &operatorv1.InstallationSpec{}

	Describe("voltron", func() {
		cloudResources := render.ManagerCloudResources{
			VoltronExtraEnv: map[string]string{
				"VOLTRON_EXTRA_ENVIRONMENT_VARIABLE1": "value1",
				"VOLTRON_EXTRA_ENVIRONMENT_VARIABLE3": "value3",
				"VOLTRON_EXTRA_ENVIRONMENT_VARIABLE2": "value2",
				"VOLTRON_K8S_CLIENT_QPS":              "42",
			},
		}
		resources, _ := renderObjects(renderConfig{
			cloud:                 true,
			oidc:                  false,
			managementCluster:     nil,
			installation:          installation,
			voltronMetricsEnabled: true,
			ns:                    render.ManagerNamespace,
			cloudResources:        cloudResources,
			// We create a tenant with an empty namespace
			// to simulate a single tenant configuration
			tenant: &operatorv1.Tenant{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tenant",
					Namespace: "",
				},
				Spec: operatorv1.TenantSpec{
					ID: "tenant-a",
				},
			},
		})

		deployment := rtest.GetResource(resources, render.ManagerDeploymentName, render.ManagerNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		template := deployment.Spec.Template.Spec

		var voltron corev1.Container
		BeforeEach(func() {
			Expect(len(template.Containers)).Should(Equal(2))
			voltron = template.Containers[1]
		})

		It("should set image correctly", func() {
			Expect(voltron.Image).Should(Equal(components.CalicoRegistry + components.CalicoImagePath + components.ComponentCalico.Image + ":" + components.ComponentCalico.Version))
		})

		It("should have env vars", func() {
			Expect(voltron.Env).Should(ContainElements(
				corev1.EnvVar{Name: "VOLTRON_CHECK_MANAGED_CLUSTER_AUTHORIZATION_BEFORE_PROXY", Value: "true"},
			))
		})

		It("should have default env vars overwritten by configmap override", func() {
			Expect(voltron.Env).ShouldNot(ContainElements(
				corev1.EnvVar{Name: "VOLTRON_K8S_CLIENT_QPS", Value: "20"},
			))
			Expect(voltron.Env).Should(ContainElements(
				corev1.EnvVar{Name: "VOLTRON_K8S_CLIENT_QPS", Value: "42"},
			))
		})

		It("should have env vars appended from configmap override in correct order", func() {
			Expect(len(voltron.Env)).To(BeNumerically(">=", 4))
			Expect(voltron.Env[len(voltron.Env)-3:]).Should(Equal([]corev1.EnvVar{
				{Name: "VOLTRON_EXTRA_ENVIRONMENT_VARIABLE1", Value: "value1"},
				{Name: "VOLTRON_EXTRA_ENVIRONMENT_VARIABLE2", Value: "value2"},
				{Name: "VOLTRON_EXTRA_ENVIRONMENT_VARIABLE3", Value: "value3"},
			}))
		})

		It("should not enable cloud voltron decorations when Cloud is false", func() {
			nonCloud, _ := renderObjects(renderConfig{
				cloud:        false,
				installation: installation,
				ns:           render.ManagerNamespace,
				tenant: &operatorv1.Tenant{
					ObjectMeta: metav1.ObjectMeta{Name: "tenant"},
					Spec:       operatorv1.TenantSpec{ID: "tenant-a"},
				},
			})
			d := rtest.GetResource(nonCloud, render.ManagerDeploymentName, render.ManagerNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(d.Spec.Template.Spec.Containers[1].Env).ShouldNot(ContainElement(
				corev1.EnvVar{Name: "VOLTRON_CHECK_MANAGED_CLUSTER_AUTHORIZATION_BEFORE_PROXY", Value: "true"},
			))
		})
	})
})
