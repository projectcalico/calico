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

package render

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
	rtest "github.com/tigera/operator/pkg/render/common/test"
)

var _ = Describe("AWS SecurityGroup Setup rendering tests", func() {
	var cfg *AWSSGSetupConfiguration

	BeforeEach(func() {
		cfg = &AWSSGSetupConfiguration{
			PullSecrets:     []corev1.LocalObjectReference{},
			Installation:    &operatorv1.InstallationSpec{},
			HostedOpenShift: false,
		}
	})

	It("should render AWS SecurityGroup Setup resources", func() {
		component, err := AWSSecurityGroupSetup(cfg)
		Expect(err).NotTo(HaveOccurred())
		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())

		toCreate, toDelete := component.Objects()

		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{"tigera-aws-security-group-setup", "tigera-operator", "", "v1", "ServiceAccount"},
			{"tigera-aws-security-group-setup", "kube-system", "rbac.authorization.k8s.io", "v1", "Role"},
			{"tigera-aws-security-group-setup", "kube-system", "rbac.authorization.k8s.io", "v1", "RoleBinding"},
			{"aws-security-group-setup-1", "tigera-operator", "batch", "v1", "Job"},
		}

		Expect(len(toCreate)).To(Equal(len(expectedResources)))

		for i, expectedRes := range expectedResources {
			obj := toCreate[i]
			rtest.ExpectResourceTypeAndObjectMetadata(obj, expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}

		Expect(toDelete).To(BeNil())
	})

	It("should render Setup Job specs correctly", func() {
		component, err := AWSSecurityGroupSetup(cfg)
		Expect(err).NotTo(HaveOccurred())
		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		toCreate, _ := component.Objects()

		job, ok := rtest.GetResource(toCreate, "aws-security-group-setup-1", "tigera-operator", "batch", "v1", "Job").(*batchv1.Job)
		Expect(ok).To(BeTrue())

		Expect(job.Spec.Template.Spec.Containers).To(HaveLen(1))

		Expect(*job.Spec.Template.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
		Expect(*job.Spec.Template.Spec.Containers[0].SecurityContext.Privileged).To(BeFalse())
		Expect(*job.Spec.Template.Spec.Containers[0].SecurityContext.RunAsGroup).To(BeEquivalentTo(10001))
		Expect(*job.Spec.Template.Spec.Containers[0].SecurityContext.RunAsNonRoot).To(BeTrue())
		Expect(*job.Spec.Template.Spec.Containers[0].SecurityContext.RunAsUser).To(BeEquivalentTo(10001))
		Expect(job.Spec.Template.Spec.Containers[0].SecurityContext.Capabilities).To(Equal(
			&corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		))
		Expect(job.Spec.Template.Spec.Containers[0].SecurityContext.SeccompProfile).To(Equal(
			&corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			}))
		expectedEnv := []corev1.EnvVar{
			{
				Name:  "OPENSHIFT",
				Value: "true",
			},
			{
				Name:  "REQUIRE_AWS",
				Value: "true",
			},
			{
				Name:  "KUBELET_KUBECONFIG",
				Value: "/etc/kubernetes/kubeconfig",
			},
		}
		Expect(job.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedEnv))
	})

	It("should render Setup Job env correctly when in an HCP hosted cluster", func() {
		cfg.HostedOpenShift = true
		component, err := AWSSecurityGroupSetup(cfg)
		Expect(err).NotTo(HaveOccurred())
		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		toCreate, _ := component.Objects()

		job, ok := rtest.GetResource(toCreate, "aws-security-group-setup-1", "tigera-operator", "batch", "v1", "Job").(*batchv1.Job)
		Expect(ok).To(BeTrue())

		Expect(job.Spec.Template.Spec.Containers).To(HaveLen(1))

		expectedEnv := []corev1.EnvVar{
			{
				Name:  "OPENSHIFT",
				Value: "true",
			},
			{
				Name:  "REQUIRE_AWS",
				Value: "true",
			},
			{
				Name:  "KUBELET_KUBECONFIG",
				Value: "/etc/kubernetes/kubeconfig",
			},
			{
				Name:  "HOSTED_OPENSHIFT",
				Value: "true",
			},
		}
		Expect(job.Spec.Template.Spec.Containers[0].Env).To(ConsistOf(expectedEnv))
	})
})
