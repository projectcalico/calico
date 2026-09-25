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

func renderCalicoResource(t *testing.T, templatePath, kind, name string, into any) {
	t.Helper()
	renderCalicoResourceWith(t, map[string]string{
		"datastore": "kubernetes",
		"network":   "calico",
		"useV3CRDs": "true",
	}, templatePath, kind, name, into)
}

func renderCalicoResourceWith(t *testing.T, values map[string]string, templatePath, kind, name string, into any) {
	t.Helper()
	g := NewWithT(t)

	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("skipping chart render tests since 'helm' is not installed")
	}

	chartPath, err := filepath.Abs("../calico")
	g.Expect(err).ToNot(HaveOccurred())

	options := &helm.Options{SetValues: values}
	output, err := helm.RenderTemplateE(t, options, chartPath, "calico", []string{templatePath})
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
