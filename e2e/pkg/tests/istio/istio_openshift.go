// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
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

package istio

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/onsi/ginkgo/v2"
	gomega "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/client"
)

// --- Istio OpenShift Platform Configuration Validation ---
//
// Validates that when Istio Ambient Mode is deployed on OpenShift, the operator
// correctly sets global.platform=openshift, activating the upstream Istio
// OpenShift profile on all Helm charts (CNI, istiod, ztunnel).
//
// The profile configures:
//   - CNI paths: /var/lib/cni/bin, /etc/cni/multus/net.d (Multus provider)
//   - Privileged SCC access for istio-cni and ztunnel
//   - SELinux: spc_t context on ztunnel
//   - Platform-aware istiod configuration
//   - Operator RBAC for NetworkAttachmentDefinition (Multus)
var _ = describe.CalicoDescribe(
	describe.WithSerial(),
	describe.WithTeam(describe.Core),
	describe.WithFeature("Istio"),
	describe.WithCategory(describe.Networking),
	"Istio OpenShift Platform Configuration",
	func() {
		f := utils.NewDefaultFramework("istio-openshift")

		var cli ctrlclient.Client

		ginkgo.BeforeEach(func() {
			var err error
			cli, err = client.New(f.ClientConfig())
			gomega.Expect(err).NotTo(gomega.HaveOccurred(), "Failed to create controller-runtime client")

			// Skip if not running on OpenShift.
			if !utils.IsOpenShift(f) {
				ginkgo.Skip("Skipping OpenShift-specific Istio tests on non-OpenShift cluster")
			}
		})

		// Test: Verify Istio deploys correctly on OpenShift with the platform profile.
		//
		// User journey: Enable Istio ambient mode on an OpenShift cluster, then verify
		// that the operator correctly activates the upstream Istio OpenShift profile on
		// all Helm charts. The profile adapts CNI paths for Multus, grants privileged
		// SCC access to Istio components, sets SELinux contexts for ztunnel, configures
		// istiod for OpenShift platform awareness, and ensures the operator has RBAC
		// to manage NetworkAttachmentDefinitions.
		ginkgo.It("should deploy Istio with correct OpenShift platform configuration", func(ctx context.Context) {
			// Enable Istio ambient mode so the operator renders the OpenShift profile.
			ginkgo.By("Ensuring Istio ambient mode is enabled")
			enableIstioAmbientMode(ctx, cli)

			// Verify all Istio pods start without permission or path errors.
			ginkgo.By("Verifying all Istio pods are Running without errors")
			expectNoIstioPodErrors(ctx, cli)

			// Verify istio-cni-node uses OpenShift CNI paths (/var/lib/cni/bin, /etc/cni/multus/net.d)
			// instead of the default /opt/cni/bin.
			ginkgo.By("Verifying istio-cni-node uses OpenShift CNI paths")
			expectOpenShiftCNIPaths(ctx, cli)

			// Verify istio-cni has a ClusterRole granting "use" on the "privileged" SCC,
			// required for the CNI plugin to run on OpenShift.
			ginkgo.By("Verifying istio-cni ClusterRole has SCC use privileged rules")
			expectClusterRoleSCCRules(ctx, cli, "istio-cni")

			// Verify ztunnel has a ClusterRole granting "use" on the "privileged" SCC,
			// required for the ztunnel DaemonSet to run on OpenShift.
			ginkgo.By("Verifying ztunnel ClusterRole has SCC use privileged rules")
			expectClusterRoleSCCRules(ctx, cli, "ztunnel")

			// Verify ztunnel runs with SELinux type spc_t, required on SELinux-enforcing
			// OpenShift nodes.
			ginkgo.By("Verifying ztunnel has SELinux spc_t context")
			expectZtunnelSELinuxContext(ctx, cli)

			// Verify istiod has PLATFORM=openshift and CA_TRUSTED_NODE_ACCOUNTS env vars
			// for OpenShift-specific behavior (e.g., trusting ztunnel service accounts).
			ginkgo.By("Verifying istiod has PLATFORM=openshift and CA_TRUSTED_NODE_ACCOUNTS env vars")
			expectIstiodOpenShiftEnvVars(ctx, cli)

			// Verify the operator has RBAC to create and manage NetworkAttachmentDefinitions,
			// required for Multus CNI integration on OpenShift.
			ginkgo.By("Verifying tigera-operator ClusterRole has NetworkAttachmentDefinition RBAC")
			expectOperatorNADRBAC(ctx, cli)
		}, ginkgo.SpecTimeout(10*time.Minute))
	},
)

// expectNoIstioPodErrors verifies all Istio pods are Running and that istio-cni-node
// logs don't contain known error patterns from the OpenShift tickets.
func expectNoIstioPodErrors(ctx context.Context, cli ctrlclient.Client) {
	getCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	podList := &corev1.PodList{}
	err := cli.List(getCtx, podList, ctrlclient.InNamespace(istioNamespace))
	gomega.Expect(err).NotTo(gomega.HaveOccurred(), "Failed to list pods in %s", istioNamespace)

	// Filter to Istio pods only.
	var istioPods []corev1.Pod
	for _, pod := range podList.Items {
		name := pod.Name
		if strings.HasPrefix(name, "istio-cni-node") ||
			strings.HasPrefix(name, "ztunnel") ||
			strings.HasPrefix(name, "istiod") {
			istioPods = append(istioPods, pod)
		}
	}
	gomega.Expect(istioPods).NotTo(gomega.BeEmpty(), "Expected Istio pods in namespace %s", istioNamespace)

	// Verify all Istio pods are Running with no CrashLoopBackOff.
	for _, pod := range istioPods {
		gomega.Expect(pod.Status.Phase).To(gomega.Equal(corev1.PodRunning),
			"Istio pod %s should be Running, got %s", pod.Name, pod.Status.Phase)
		for _, cs := range pod.Status.ContainerStatuses {
			if cs.State.Waiting != nil {
				gomega.Expect(cs.State.Waiting.Reason).NotTo(gomega.Equal("CrashLoopBackOff"),
					"Istio pod %s container %s should not be in CrashLoopBackOff", pod.Name, cs.Name)
			}
		}
	}

	// Check istio-cni-node logs for known error patterns.
	k := utils.Kubectl{}
	logs, err := k.Logs(istioNamespace, "app=istio-cni-node", "")
	gomega.Expect(err).NotTo(gomega.HaveOccurred(), "Failed to get istio-cni-node logs")

	errorPatterns := []string{
		"no such file or directory",
		"permission denied",
		"read-only file system",
	}
	lowerLogs := strings.ToLower(logs)
	for _, pattern := range errorPatterns {
		gomega.Expect(lowerLogs).NotTo(gomega.ContainSubstring(pattern),
			"istio-cni-node logs should not contain %q", pattern)
	}
}

// expectOpenShiftCNIPaths verifies the istio-cni-node DaemonSet uses OpenShift-specific
// CNI paths: /var/lib/cni/bin for binaries and /etc/cni/multus/net.d for config.
func expectOpenShiftCNIPaths(ctx context.Context, cli ctrlclient.Client) {
	getCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	ds := &appsv1.DaemonSet{}
	err := cli.Get(getCtx, ctrlclient.ObjectKey{Namespace: istioNamespace, Name: "istio-cni-node"}, ds)
	gomega.Expect(err).NotTo(gomega.HaveOccurred(), "Failed to get istio-cni-node DaemonSet")

	volumes := ds.Spec.Template.Spec.Volumes

	// Validate cni-bin-dir volume hostPath.
	cniBinVol := findVolume(volumes, "cni-bin-dir")
	gomega.Expect(cniBinVol).NotTo(gomega.BeNil(), "cni-bin-dir volume should exist")
	gomega.Expect(cniBinVol.HostPath).NotTo(gomega.BeNil(), "cni-bin-dir should be a hostPath volume")
	gomega.Expect(cniBinVol.HostPath.Path).To(gomega.Equal("/var/lib/cni/bin"),
		"cni-bin-dir should use OpenShift path /var/lib/cni/bin")

	// Validate cni-net-dir volume hostPath.
	cniNetVol := findVolume(volumes, "cni-net-dir")
	gomega.Expect(cniNetVol).NotTo(gomega.BeNil(), "cni-net-dir volume should exist")
	gomega.Expect(cniNetVol.HostPath).NotTo(gomega.BeNil(), "cni-net-dir should be a hostPath volume")
	gomega.Expect(cniNetVol.HostPath.Path).To(gomega.Equal("/etc/cni/multus/net.d"),
		"cni-net-dir should use OpenShift/Multus path /etc/cni/multus/net.d")
}

// expectZtunnelSELinuxContext verifies the ztunnel DaemonSet has SELinux type spc_t,
// which is required on OpenShift.
func expectZtunnelSELinuxContext(ctx context.Context, cli ctrlclient.Client) {
	getCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	ds := &appsv1.DaemonSet{}
	err := cli.Get(getCtx, ctrlclient.ObjectKey{Namespace: istioNamespace, Name: "ztunnel"}, ds)
	gomega.Expect(err).NotTo(gomega.HaveOccurred(), "Failed to get ztunnel DaemonSet")

	// Check pod-level first, then container-level (container takes precedence).
	var seLinuxType string
	if sc := ds.Spec.Template.Spec.SecurityContext; sc != nil && sc.SELinuxOptions != nil {
		seLinuxType = sc.SELinuxOptions.Type
	}
	for _, c := range ds.Spec.Template.Spec.Containers {
		if c.SecurityContext != nil && c.SecurityContext.SELinuxOptions != nil {
			seLinuxType = c.SecurityContext.SELinuxOptions.Type
		}
	}

	gomega.Expect(seLinuxType).To(gomega.Equal("spc_t"),
		"ztunnel SELinux type should be spc_t for OpenShift")
}

// expectIstiodOpenShiftEnvVars verifies the istiod deployment has PLATFORM=openshift
// and CA_TRUSTED_NODE_ACCOUNTS environment variables.
func expectIstiodOpenShiftEnvVars(ctx context.Context, cli ctrlclient.Client) {
	getCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	podList := &corev1.PodList{}
	err := cli.List(getCtx, podList,
		ctrlclient.InNamespace(istioNamespace),
		ctrlclient.MatchingLabels{"app": "istiod"},
	)
	gomega.Expect(err).NotTo(gomega.HaveOccurred(), "Failed to list istiod pods")
	gomega.Expect(podList.Items).NotTo(gomega.BeEmpty(), "Expected at least one istiod pod")

	// Find the discovery container (or fall back to first container).
	pod := podList.Items[0]
	var container *corev1.Container
	for i := range pod.Spec.Containers {
		if pod.Spec.Containers[i].Name == "discovery" {
			container = &pod.Spec.Containers[i]
			break
		}
	}
	if container == nil {
		container = &pod.Spec.Containers[0]
	}

	// CA_TRUSTED_NODE_ACCOUNTS must reference the namespace where ztunnel actually runs.
	// The upstream Istio OpenShift profile defaults to "kube-system/ztunnel", but the
	// Tigera operator deploys ztunnel to calico-system. The operator overrides this via
	// the trustedZtunnelNamespace Helm value. See: EV-6485.
	expectedEnvVars := map[string]string{
		"PLATFORM":                 "openshift",
		"CA_TRUSTED_NODE_ACCOUNTS": istioNamespace + "/ztunnel",
	}

	for envName, expectedValue := range expectedEnvVars {
		found := false
		for _, env := range container.Env {
			if env.Name == envName {
				gomega.Expect(env.Value).To(gomega.Equal(expectedValue),
					"istiod env var %s should be %q, got %q", envName, expectedValue, env.Value)
				found = true
				break
			}
		}
		gomega.Expect(found).To(gomega.BeTrue(),
			"istiod should have env var %s=%s", envName, expectedValue)
	}
}

// expectOperatorNADRBAC verifies the tigera-operator ClusterRole has RBAC rules for
// NetworkAttachmentDefinition (k8s.cni.cncf.io), required for Multus on OpenShift.
func expectOperatorNADRBAC(ctx context.Context, cli ctrlclient.Client) {
	getCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// List all ClusterRoles and find ones matching tigera-operator.
	clusterRoleList := &rbacv1.ClusterRoleList{}
	err := cli.List(getCtx, clusterRoleList)
	gomega.Expect(err).NotTo(gomega.HaveOccurred(), "Failed to list ClusterRoles")

	var operatorRoles []rbacv1.ClusterRole
	for _, cr := range clusterRoleList.Items {
		if strings.Contains(cr.Name, "tigera-operator") {
			operatorRoles = append(operatorRoles, cr)
		}
	}
	gomega.Expect(operatorRoles).NotTo(gomega.BeEmpty(),
		"Expected at least one ClusterRole matching tigera-operator")

	// Look for NAD create rule (any NAD) and NAD manage rule (istio-cni specific).
	foundNADCreate := false
	foundNADManage := false

	for _, role := range operatorRoles {
		for _, rule := range role.Rules {
			if !slices.Contains(rule.APIGroups, "k8s.cni.cncf.io") {
				continue
			}
			if !slices.Contains(rule.Resources, "network-attachment-definitions") {
				continue
			}

			// Create rule: can create any NAD (no resourceNames restriction).
			if slices.Contains(rule.Verbs, "create") && len(rule.ResourceNames) == 0 {
				foundNADCreate = true
			}

			// Manage rule: get/update/delete scoped to istio-cni.
			if slices.Contains(rule.ResourceNames, "istio-cni") &&
				slices.Contains(rule.Verbs, "get") &&
				slices.Contains(rule.Verbs, "update") &&
				slices.Contains(rule.Verbs, "delete") {
				foundNADManage = true
			}
		}
		if foundNADCreate && foundNADManage {
			break
		}
	}

	gomega.Expect(foundNADCreate).To(gomega.BeTrue(),
		"tigera-operator should have ClusterRole rule to create NetworkAttachmentDefinitions")
	gomega.Expect(foundNADManage).To(gomega.BeTrue(),
		"tigera-operator should have ClusterRole rule to get/update/delete istio-cni NetworkAttachmentDefinition")
}

// expectClusterRoleSCCRules verifies that a ClusterRole matching the partial name has
// rules granting "use" on the "privileged" SecurityContextConstraint.
func expectClusterRoleSCCRules(ctx context.Context, cli ctrlclient.Client, partialName string) {
	getCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	clusterRoleList := &rbacv1.ClusterRoleList{}
	err := cli.List(getCtx, clusterRoleList)
	gomega.Expect(err).NotTo(gomega.HaveOccurred(), "Failed to list ClusterRoles")

	// Find ClusterRoles matching the partial name.
	var matchingRoles []rbacv1.ClusterRole
	for _, cr := range clusterRoleList.Items {
		if strings.Contains(cr.Name, partialName) {
			matchingRoles = append(matchingRoles, cr)
		}
	}
	gomega.Expect(matchingRoles).NotTo(gomega.BeEmpty(),
		"Expected at least one ClusterRole matching %q", partialName)

	// Check that at least one matching role has the SCC rule:
	// apiGroups: ["security.openshift.io"], resources: ["securitycontextconstraints"],
	// verbs: ["use"], resourceNames: ["privileged"]
	foundSCCRule := false
	for _, role := range matchingRoles {
		for _, rule := range role.Rules {
			if slices.Contains(rule.APIGroups, "security.openshift.io") &&
				slices.Contains(rule.Resources, "securitycontextconstraints") &&
				slices.Contains(rule.Verbs, "use") &&
				slices.Contains(rule.ResourceNames, "privileged") {
				foundSCCRule = true
				break
			}
		}
		if foundSCCRule {
			break
		}
	}
	gomega.Expect(foundSCCRule).To(gomega.BeTrue(),
		"ClusterRole matching %q should have SCC rule granting 'use' on 'privileged' SecurityContextConstraint", partialName)
}

func findVolume(volumes []corev1.Volume, name string) *corev1.Volume {
	for i := range volumes {
		if volumes[i].Name == name {
			return &volumes[i]
		}
	}
	return nil
}
