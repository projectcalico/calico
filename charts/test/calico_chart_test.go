// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
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

package charttest

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gruntwork-io/terratest/modules/helm"
	. "github.com/onsi/gomega"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/yaml"
)

// The calico image declares USER 10001, so an init container that writes the host CNI
// directories has to ask for root explicitly. Without it calico-node never leaves
// Init:CrashLoopBackOff on a manifest install.
func TestCalicoNodeRunsHostWritingInitContainersAsRoot(t *testing.T) {
	g := NewWithT(t)

	var daemonSet appsv1.DaemonSet
	renderCalicoResource(t, "templates/calico-node.yaml", "DaemonSet", "calico-node", &daemonSet)

	for _, name := range []string{"upgrade-ipam", "install-cni"} {
		container := containerByName(t, daemonSet.Spec.Template.Spec.InitContainers, name)
		g.Expect(container.SecurityContext.RunAsUser).To(Equal(ptr.To[int64](0)), "%s writes to root-owned host CNI directories", name)
	}
}

// The combined calico image ships no upstream CNI plugins, so install-cni has nothing
// to copy onto the host unless cni-plugins stages them first.
func TestCalicoNodeStagesUpstreamCNIPlugins(t *testing.T) {
	g := NewWithT(t)

	var daemonSet appsv1.DaemonSet
	renderCalicoResource(t, "templates/calico-node.yaml", "DaemonSet", "calico-node", &daemonSet)

	initContainers := daemonSet.Spec.Template.Spec.InitContainers
	g.Expect(containerIndex(t, initContainers, "cni-plugins")).To(BeNumerically("<", containerIndex(t, initContainers, "install-cni")))

	staging := containerByName(t, initContainers, "cni-plugins")
	g.Expect(staging.VolumeMounts).To(ContainElement(corev1.VolumeMount{Name: "cni-plugins-stage", MountPath: "/stage"}))
	g.Expect(staging.SecurityContext.RunAsUser).To(Equal(ptr.To[int64](0)))

	installCNI := containerByName(t, initContainers, "install-cni")
	g.Expect(installCNI.VolumeMounts).To(ContainElement(corev1.VolumeMount{Name: "cni-plugins-stage", MountPath: "/opt/cni/bin"}))

	g.Expect(daemonSet.Spec.Template.Spec.Volumes).To(ContainElement(corev1.Volume{
		Name:         "cni-plugins-stage",
		VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
	}))
}

// The probes reach the health server that the container's own flag starts, so a
// port they disagree on leaves kube-controllers failing its liveness probe for good.
func TestCalicoKubeControllersProbesMatchItsHealthPort(t *testing.T) {
	g := NewWithT(t)

	var deployment appsv1.Deployment
	renderCalicoResource(t, "templates/calico-kube-controllers.yaml", "Deployment", "calico-kube-controllers", &deployment)

	container := containerByName(t, deployment.Spec.Template.Spec.Containers, "calico-kube-controllers")

	var port string
	for _, arg := range container.Args {
		if value, ok := strings.CutPrefix(arg, "--health-port="); ok {
			port = value
		}
	}
	g.Expect(port).ToNot(BeEmpty(), "the container has to start a health server for the probes to reach")

	g.Expect(container.LivenessProbe.Exec.Command).To(Equal([]string{"/usr/bin/calico", "health", "--port=" + port, "--type=liveness"}))
	g.Expect(container.ReadinessProbe.Exec.Command).To(Equal([]string{"/usr/bin/calico", "health", "--port=" + port, "--type=readiness"}))
}

func TestCalicoWebhooksKeepsTheServerUnprivileged(t *testing.T) {
	g := NewWithT(t)

	var deployment appsv1.Deployment
	renderCalicoResource(t, "templates/calico-webhooks.yaml", "Deployment", "calico-webhooks", &deployment)

	container := containerByName(t, deployment.Spec.Template.Spec.Containers, "calico-webhooks")
	g.Expect(container.SecurityContext.RunAsUser).To(Equal(ptr.To[int64](10001)))
	g.Expect(container.SecurityContext.RunAsNonRoot).To(Equal(ptr.To(true)))
}

// The TLS flags live on the nested webhook command, so "component webhook" alone reaches
// the parent group and the server exits with "unknown flag: --tls-cert-file".
func TestCalicoWebhooksInvokesTheNestedWebhookCommand(t *testing.T) {
	g := NewWithT(t)

	var deployment appsv1.Deployment
	renderCalicoResource(t, "templates/calico-webhooks.yaml", "Deployment", "calico-webhooks", &deployment)

	container := containerByName(t, deployment.Spec.Template.Spec.Containers, "calico-webhooks")
	g.Expect(container.Args).To(Equal([]string{
		"component",
		"webhooks",
		"webhook",
		"--tls-cert-file=/certs/tls.crt",
		"--tls-private-key-file=/certs/tls.key",
	}))
}

// The policies over built-in Kubernetes resources apply whichever Calico API the manifest serves.
func TestCalicoRendersTheCNIAnnotationPolicy(t *testing.T) {
	const name = "protect-cni-annotations.projectcalico.org"

	for _, useV3CRDs := range []string{"true", "false"} {
		t.Run("useV3CRDs="+useV3CRDs, func(t *testing.T) {
			values := map[string]string{
				"datastore": "kubernetes",
				"network":   "calico",
				"useV3CRDs": useV3CRDs,
			}

			var policy admissionregistrationv1.ValidatingAdmissionPolicy
			renderCalicoResourceWith(t, values, "templates/admission-policies.yaml", "ValidatingAdmissionPolicy", name, &policy)

			var binding admissionregistrationv1.ValidatingAdmissionPolicyBinding
			renderCalicoResourceWith(t, values, "templates/admission-policies.yaml", "ValidatingAdmissionPolicyBinding", name, &binding)
			NewWithT(t).Expect(binding.Spec.PolicyName).To(Equal(name))
		})
	}
}

// The mutating policy renders at the newest MutatingAdmissionPolicy version the cluster serves.
func TestCalicoRendersTheCNIAnnotationMutatingPolicy(t *testing.T) {
	const name = "strip-cni-annotations.projectcalico.org"

	for _, tc := range []struct {
		served string
		want   string
	}{
		{served: "", want: "admissionregistration.k8s.io/v1beta1"},
		{served: "admissionregistration.k8s.io/v1/MutatingAdmissionPolicy", want: "admissionregistration.k8s.io/v1"},
		{served: "admissionregistration.k8s.io/v1alpha1/MutatingAdmissionPolicy", want: "admissionregistration.k8s.io/v1alpha1"},
	} {
		t.Run("served="+tc.served, func(t *testing.T) {
			g := NewWithT(t)
			values := map[string]string{
				"datastore": "kubernetes",
				"network":   "calico",
				"useV3CRDs": "false",
			}
			var args []string
			if tc.served != "" {
				args = []string{"--api-versions", tc.served}
			}

			var policy admissionregistrationv1.MutatingAdmissionPolicy
			renderCalicoResourceWith(t, values, "templates/admission-policies.yaml", "MutatingAdmissionPolicy", name, &policy, args...)
			g.Expect(policy.APIVersion).To(Equal(tc.want))

			var binding admissionregistrationv1.MutatingAdmissionPolicyBinding
			renderCalicoResourceWith(t, values, "templates/admission-policies.yaml", "MutatingAdmissionPolicyBinding", name, &binding, args...)
			g.Expect(binding.APIVersion).To(Equal(tc.want))
			g.Expect(binding.Spec.PolicyName).To(Equal(name))
		})
	}
}

// The CNI plugin is let through protect-cni-annotations.projectcalico.org by a permission its role
// carries. On canal it runs as the node's own service account, so there the node role carries it too.
func TestCalicoGrantsTheCNIPluginItsAnnotationPermission(t *testing.T) {
	grant := rbacv1.PolicyRule{
		APIGroups: []string{"projectcalico.org"},
		Resources: []string{"cniannotations"},
		Verbs:     []string{"write"},
	}

	for _, tc := range []struct {
		network        string
		nodeRoleGrants bool
	}{
		{network: "calico", nodeRoleGrants: false},
		{network: "flannel", nodeRoleGrants: true},
	} {
		t.Run("network="+tc.network, func(t *testing.T) {
			g := NewWithT(t)
			values := map[string]string{"datastore": "kubernetes", "network": tc.network}

			var cniRole rbacv1.ClusterRole
			renderCalicoResourceWith(t, values, "templates/calico-node-rbac.yaml", "ClusterRole", "calico-cni-plugin", &cniRole)
			g.Expect(cniRole.Rules).To(ContainElement(grant))

			var nodeRole rbacv1.ClusterRole
			renderCalicoResourceWith(t, values, "templates/calico-node-rbac.yaml", "ClusterRole", "calico-node", &nodeRole)
			if tc.nodeRoleGrants {
				g.Expect(nodeRole.Rules).To(ContainElement(grant))
			} else {
				g.Expect(nodeRole.Rules).NotTo(ContainElement(grant))
			}
		})
	}
}

// On etcd the CNI plugin writes workload endpoints to etcd, not to these pod annotations, so neither
// policy is rendered.
func TestCalicoOmitsTheCNIAnnotationPoliciesOnEtcd(t *testing.T) {
	g := NewWithT(t)
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("skipping chart render tests since 'helm' is not installed")
	}
	chartPath, err := filepath.Abs("../calico")
	g.Expect(err).ToNot(HaveOccurred())

	for _, network := range []string{"calico", "flannel"} {
		options := &helm.Options{SetValues: map[string]string{"datastore": "etcd", "network": network}}
		output, err := helm.RenderTemplateE(t, options, chartPath, "calico", nil)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(output).NotTo(ContainSubstring("protect-cni-annotations.projectcalico.org"), network)
		g.Expect(output).NotTo(ContainSubstring("strip-cni-annotations.projectcalico.org"), network)
	}
}

func renderCalicoResource(t *testing.T, templatePath, kind, name string, into any) {
	t.Helper()
	renderCalicoResourceWith(t, map[string]string{
		"datastore": "kubernetes",
		"network":   "calico",
		"useV3CRDs": "true",
	}, templatePath, kind, name, into)
}

func renderCalicoResourceWith(t *testing.T, values map[string]string, templatePath, kind, name string, into any, templateArgs ...string) {
	t.Helper()
	g := NewWithT(t)

	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("skipping chart render tests since 'helm' is not installed")
	}

	chartPath, err := filepath.Abs("../calico")
	g.Expect(err).ToNot(HaveOccurred())

	options := &helm.Options{SetValues: values}
	output, err := helm.RenderTemplateE(t, options, chartPath, "calico", []string{templatePath}, templateArgs...)
	g.Expect(err).ToNot(HaveOccurred())

	for _, doc := range strings.Split(output, "\n---") {
		var meta metav1.PartialObjectMetadata
		if err := yaml.Unmarshal([]byte(doc), &meta); err != nil {
			continue
		}
		if meta.Kind != kind || meta.Name != name {
			continue
		}
		g.Expect(yaml.Unmarshal([]byte(doc), into)).To(Succeed())
		return
	}
	t.Fatalf("%s %q was not rendered from %s", kind, name, templatePath)
}

func containerIndex(t *testing.T, containers []corev1.Container, name string) int {
	t.Helper()

	for i, container := range containers {
		if container.Name == name {
			return i
		}
	}
	t.Fatalf("container %q not found", name)
	return -1
}

func containerByName(t *testing.T, containers []corev1.Container, name string) corev1.Container {
	t.Helper()

	for _, container := range containers {
		if container.Name == name {
			return container
		}
	}
	t.Fatalf("container %q not found", name)
	return corev1.Container{}
}
