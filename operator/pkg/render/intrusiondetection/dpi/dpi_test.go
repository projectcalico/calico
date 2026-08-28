// Copyright (c) 2021-2026 Tigera, Inc. All rights reserved.

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

package dpi_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
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
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/intrusiondetection/dpi"
	"github.com/tigera/operator/pkg/render/testutils"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

var (
	defaultMode int32 = 420
	dirOrCreate       = corev1.HostPathDirectoryOrCreate

	ids = &operatorv1.IntrusionDetection{
		TypeMeta:   metav1.TypeMeta{Kind: "IntrusionDetection", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
		Spec: operatorv1.IntrusionDetectionSpec{
			ComponentResources: []operatorv1.IntrusionDetectionComponentResource{
				{
					ComponentName: operatorv1.ComponentNameDeepPacketInspection,
					ResourceRequirements: &corev1.ResourceRequirements{
						Limits: corev1.ResourceList{
							corev1.ResourceMemory: resource.MustParse(dpi.DefaultMemoryLimit),
							corev1.ResourceCPU:    resource.MustParse(dpi.DefaultCPULimit),
						},
						Requests: corev1.ResourceList{
							corev1.ResourceMemory: resource.MustParse(dpi.DefaultMemoryRequest),
							corev1.ResourceCPU:    resource.MustParse(dpi.DefaultCPURequest),
						},
					},
				},
			},
		},
	}

	expectedClusterRoleRules = []rbacv1.PolicyRule{
		{
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"deeppacketinspections"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"deeppacketinspections/status"},
			Verbs:     []string{"update"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"endpoints", "services"},
			Verbs:     []string{"watch", "list", "get"},
		},
		{
			APIGroups: []string{"discovery.k8s.io"},
			Resources: []string{"endpointslices"},
			Verbs:     []string{"watch", "list", "get"},
		},
	}

	expectedLinseedClusterRoleRules = []rbacv1.PolicyRule{
		{
			APIGroups: []string{"linseed.tigera.io"},
			Resources: []string{"events"},
			Verbs:     []string{"create"},
		},
	}

	expectedCRB = rbacv1.RoleBinding{
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      dpi.DeepPacketInspectionName,
				Namespace: dpi.DeepPacketInspectionNamespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     dpi.DeepPacketInspectionName,
		},
	}

	expectedLinseedCRB = rbacv1.RoleBinding{
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      dpi.DeepPacketInspectionName,
				Namespace: dpi.DeepPacketInspectionNamespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     dpi.DeepPacketInspectionLinseedRBACName,
		},
	}

	expectedVolumes = []corev1.Volume{
		{
			Name: "tigera-ca-bundle",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "tigera-ca-bundle",
					},
				},
			},
		},
		{
			Name: "node-certs",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName:  render.NodeTLSSecretName,
					DefaultMode: &defaultMode,
				},
			},
		},
		{
			Name: "log-snort-alters",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/var/log/calico/snort-alerts",
					Type: &dirOrCreate,
				},
			},
		},
	}

	expectedVolumeMounts = []corev1.VolumeMount{
		{MountPath: "/etc/pki/tls/certs", Name: "tigera-ca-bundle", ReadOnly: true},
		{MountPath: "/node-certs", Name: "node-certs", ReadOnly: true},
		{MountPath: "/var/log/calico/snort-alerts", Name: "log-snort-alters"},
	}

	pullSecrets = []*corev1.Secret{{
		TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "pull-secret", Namespace: common.OperatorNamespace()},
	}}
)

type resourceTestObj struct {
	name    string
	ns      string
	group   string
	version string
	kind    string
}

var _ = Describe("DPI rendering tests", func() {
	var (
		clusterDomain = "cluster.local"
		installation  *operatorv1.InstallationSpec
		typhaNodeTLS  *render.TyphaNodeTLS
		dpiCertSecret certificatemanagement.KeyPairInterface
		cfg           *dpi.DPIConfig
	)

	// Fetch expectations from utilities that require Ginkgo context.
	expectedUnmanagedPolicy := testutils.GetExpectedPolicyFromFile("../../testutils/expected_policies/dpi_unmanaged.json")
	expectedUnmanagedPolicyForOpenshift := testutils.GetExpectedPolicyFromFile("../../testutils/expected_policies/dpi_unmanaged_ocp.json")
	expectedManagedPolicy := testutils.GetExpectedPolicyFromFile("../../testutils/expected_policies/dpi_managed.json")
	expectedManagedPolicyForOpenshift := testutils.GetExpectedPolicyFromFile("../../testutils/expected_policies/dpi_managed_ocp.json")

	BeforeEach(func() {
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		cli := ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
		certificateManager, err := certificatemanager.Create(cli, nil, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())

		nodeKeyPair, err := certificateManager.GetOrCreateKeyPair(cli, render.NodeTLSSecretName, common.OperatorNamespace(), []string{render.FelixCommonName})
		Expect(err).NotTo(HaveOccurred())
		typhaKeyPair, err := certificateManager.GetOrCreateKeyPair(cli, render.TyphaTLSSecretName, common.OperatorNamespace(), []string{render.FelixCommonName})
		Expect(err).NotTo(HaveOccurred())
		dpiCertSecret, err = certificateManager.GetOrCreateKeyPair(cli, render.DPITLSSecretName, common.OperatorNamespace(), []string{""})
		Expect(err).NotTo(HaveOccurred())

		trustedBundle := certificateManager.CreateTrustedBundle(nodeKeyPair, typhaKeyPair, dpiCertSecret)
		typhaNodeTLS = &render.TyphaNodeTLS{
			TyphaSecret:   typhaKeyPair,
			NodeSecret:    nodeKeyPair,
			TrustedBundle: trustedBundle,
		}
		installation = &operatorv1.InstallationSpec{Registry: "testregistry.com/"}
		cfg = &dpi.DPIConfig{
			IntrusionDetection: ids,
			Installation:       installation,
			TyphaNodeTLS:       typhaNodeTLS,
			PullSecrets:        pullSecrets,
			OpenShift:          false,
			HasNoLicense:       false,
			HasNoDPIResource:   false,
			ClusterDomain:      dns.DefaultClusterDomain,
			DPICertSecret:      dpiCertSecret,
		}
	})

	It("should render all resources for deep packet inspection with default resource requirements", func() {
		component := dpi.DPI(cfg)

		resources, _ := component.Objects()

		expectedResources := []client.Object{
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"}},
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionPolicyName, Namespace: dpi.DeepPacketInspectionNamespace}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "pull-secret", Namespace: dpi.DeepPacketInspectionNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionName, Namespace: dpi.DeepPacketInspectionNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionName, Namespace: dpi.DeepPacketInspectionNamespace}, TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionLinseedRBACName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionLinseedRBACName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraOperatorSecrets, Namespace: dpi.DeepPacketInspectionNamespace}, TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
		}

		rtest.ExpectResources(resources, expectedResources)

		ds := rtest.GetResource(resources, dpi.DeepPacketInspectionName, dpi.DeepPacketInspectionNamespace, "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
		Expect(ds.Spec.Template.Spec.Containers[0].Env).Should(ContainElements(
			corev1.EnvVar{Name: "LINSEED_CLIENT_CERT", Value: "/deep-packet-inspection-tls/tls.crt"},
			corev1.EnvVar{Name: "LINSEED_CLIENT_KEY", Value: "/deep-packet-inspection-tls/tls.key"},
			corev1.EnvVar{Name: "LINSEED_TOKEN", Value: "/var/run/secrets/kubernetes.io/serviceaccount/token"},
		))
		Expect(len(ds.Spec.Template.Spec.Containers)).Should(Equal(1))
		Expect(*ds.Spec.Template.Spec.Containers[0].Resources.Requests.Cpu()).Should(Equal(resource.MustParse(dpi.DefaultCPURequest)))
		Expect(*ds.Spec.Template.Spec.Containers[0].Resources.Limits.Cpu()).Should(Equal(resource.MustParse(dpi.DefaultCPULimit)))
		Expect(*ds.Spec.Template.Spec.Containers[0].Resources.Requests.Memory()).Should(Equal(resource.MustParse(dpi.DefaultMemoryRequest)))
		Expect(*ds.Spec.Template.Spec.Containers[0].Resources.Limits.Memory()).Should(Equal(resource.MustParse(dpi.DefaultMemoryLimit)))

		validateDPIComponents(resources, false)
	})

	It("should render all resources for deep packet inspection for a management cluster", func() {
		cfg = &dpi.DPIConfig{
			IntrusionDetection: ids,
			Installation:       installation,
			TyphaNodeTLS:       typhaNodeTLS,
			PullSecrets:        pullSecrets,
			OpenShift:          false,
			HasNoLicense:       false,
			HasNoDPIResource:   false,
			ClusterDomain:      dns.DefaultClusterDomain,
			DPICertSecret:      dpiCertSecret,
			ManagementCluster:  true,
		}
		component := dpi.DPI(cfg)

		resources, _ := component.Objects()

		expectedResources := []client.Object{
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionName}},
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionPolicyName, Namespace: dpi.DeepPacketInspectionNamespace}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "pull-secret", Namespace: dpi.DeepPacketInspectionNamespace}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionNamespace, Namespace: dpi.DeepPacketInspectionNamespace}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionName}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionNamespace}},
			&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionName, Namespace: dpi.DeepPacketInspectionNamespace}, TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionLinseedRBACName}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionLinseedRBACName}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraOperatorSecrets, Namespace: dpi.DeepPacketInspectionNamespace}, TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
		}
		rtest.ExpectResources(resources, expectedResources)

		ds := rtest.GetResource(resources, dpi.DeepPacketInspectionName, dpi.DeepPacketInspectionNamespace, "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
		Expect(ds.Spec.Template.Spec.Containers[0].Env).Should(ContainElements(
			corev1.EnvVar{Name: "LINSEED_URL", Value: "https://tigera-linseed.tigera-elasticsearch.svc"},
			corev1.EnvVar{Name: "LINSEED_CLIENT_CERT", Value: "/deep-packet-inspection-tls/tls.crt"},
			corev1.EnvVar{Name: "LINSEED_CLIENT_KEY", Value: "/deep-packet-inspection-tls/tls.key"},
			corev1.EnvVar{Name: "LINSEED_TOKEN", Value: "/var/run/secrets/kubernetes.io/serviceaccount/token"},
		))
		Expect(len(ds.Spec.Template.Spec.Containers)).Should(Equal(1))
		Expect(*ds.Spec.Template.Spec.Containers[0].Resources.Requests.Cpu()).Should(Equal(resource.MustParse(dpi.DefaultCPURequest)))
		Expect(*ds.Spec.Template.Spec.Containers[0].Resources.Limits.Cpu()).Should(Equal(resource.MustParse(dpi.DefaultCPULimit)))
		Expect(*ds.Spec.Template.Spec.Containers[0].Resources.Requests.Memory()).Should(Equal(resource.MustParse(dpi.DefaultMemoryRequest)))
		Expect(*ds.Spec.Template.Spec.Containers[0].Resources.Limits.Memory()).Should(Equal(resource.MustParse(dpi.DefaultMemoryLimit)))

		validateDPIComponents(resources, false)
	})

	It("should render all resources for deep packet inspection for a managed cluster", func() {
		cfg = &dpi.DPIConfig{
			IntrusionDetection: ids,
			Installation:       installation,
			TyphaNodeTLS:       typhaNodeTLS,
			PullSecrets:        pullSecrets,
			OpenShift:          false,
			HasNoLicense:       false,
			HasNoDPIResource:   false,
			ClusterDomain:      dns.DefaultClusterDomain,
			DPICertSecret:      dpiCertSecret,
			ManagedCluster:     true,
		}
		component := dpi.DPI(cfg)

		resources, _ := component.Objects()

		expectedResources := []client.Object{
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionName}},
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionPolicyName, Namespace: dpi.DeepPacketInspectionNamespace}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "pull-secret", Namespace: dpi.DeepPacketInspectionNamespace}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionNamespace, Namespace: dpi.DeepPacketInspectionNamespace}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionName}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionNamespace}},
			&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionName, Namespace: dpi.DeepPacketInspectionNamespace}, TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-linseed", Namespace: dpi.DeepPacketInspectionNamespace}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraOperatorSecrets, Namespace: dpi.DeepPacketInspectionNamespace}, TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
		}
		rtest.ExpectResources(resources, expectedResources)

		ds := rtest.GetResource(resources, dpi.DeepPacketInspectionName, dpi.DeepPacketInspectionNamespace, "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
		Expect(ds.Spec.Template.Spec.Containers[0].Env).Should(ContainElements(
			corev1.EnvVar{Name: "LINSEED_URL", Value: "https://guardian.calico-system.svc"},
			corev1.EnvVar{Name: "LINSEED_CLIENT_CERT", Value: "/deep-packet-inspection-tls/tls.crt"},
			corev1.EnvVar{Name: "LINSEED_CLIENT_KEY", Value: "/deep-packet-inspection-tls/tls.key"},
			corev1.EnvVar{Name: "LINSEED_TOKEN", Value: render.LinseedTokenPath},
		))
		Expect(len(ds.Spec.Template.Spec.Containers)).Should(Equal(1))
		Expect(*ds.Spec.Template.Spec.Containers[0].Resources.Requests.Cpu()).Should(Equal(resource.MustParse(dpi.DefaultCPURequest)))
		Expect(*ds.Spec.Template.Spec.Containers[0].Resources.Limits.Cpu()).Should(Equal(resource.MustParse(dpi.DefaultCPULimit)))
		Expect(*ds.Spec.Template.Spec.Containers[0].Resources.Requests.Memory()).Should(Equal(resource.MustParse(dpi.DefaultMemoryRequest)))
		Expect(*ds.Spec.Template.Spec.Containers[0].Resources.Limits.Memory()).Should(Equal(resource.MustParse(dpi.DefaultMemoryLimit)))

		validateDPIComponents(resources, false)
	})

	It("Should render Linseed permissions for management clusters, even without DPI enabled", func() {
		cfg = &dpi.DPIConfig{
			IntrusionDetection: ids,
			Installation:       installation,
			TyphaNodeTLS:       typhaNodeTLS,
			PullSecrets:        pullSecrets,
			OpenShift:          false,
			HasNoLicense:       false,
			HasNoDPIResource:   true,
			ManagementCluster:  true,
			ClusterDomain:      dns.DefaultClusterDomain,
			DPICertSecret:      dpiCertSecret,
		}
		component := dpi.DPI(cfg)

		resources, _ := component.Objects()

		expectedResources := []client.Object{
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionName}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionLinseedRBACName}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionLinseedRBACName}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraOperatorSecrets, Namespace: dpi.DeepPacketInspectionNamespace}, TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
		}
		rtest.ExpectResources(resources, expectedResources)

		dpiNs := rtest.GetResource(resources, dpi.DeepPacketInspectionNamespace, "", "", "v1", "Namespace").(*corev1.Namespace)
		Expect(dpiNs).ShouldNot(BeNil())

		dpiLinseedClusterRole := rtest.GetResource(resources, dpi.DeepPacketInspectionLinseedRBACName, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(dpiLinseedClusterRole.Rules).Should(ContainElements(expectedLinseedClusterRoleRules))

		dpiLinseedClusterRoleBinding := rtest.GetResource(resources, dpi.DeepPacketInspectionLinseedRBACName, "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
		Expect(dpiLinseedClusterRoleBinding.RoleRef).Should(Equal(expectedLinseedCRB.RoleRef))
		Expect(dpiLinseedClusterRoleBinding.Subjects).Should(BeEquivalentTo(expectedLinseedCRB.Subjects))
	})

	It("should render all resources for deep packet inspection with custom resource requirements", func() {
		memoryLimit := resource.MustParse("2Gi")
		cpuLimit := resource.MustParse("2")
		ids2 := &operatorv1.IntrusionDetection{
			TypeMeta:   metav1.TypeMeta{Kind: "IntrusionDetection", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Spec: operatorv1.IntrusionDetectionSpec{
				ComponentResources: []operatorv1.IntrusionDetectionComponentResource{
					{
						ComponentName: "DeepPacketInspection",
						ResourceRequirements: &corev1.ResourceRequirements{
							Limits: corev1.ResourceList{"memory": memoryLimit, "cpu": cpuLimit},
						},
					},
				},
			},
		}

		cfg.IntrusionDetection = ids2
		cfg.OpenShift = true
		component := dpi.DPI(cfg)

		resources, _ := component.Objects()

		expectedResources := []client.Object{
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"}},
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionPolicyName, Namespace: dpi.DeepPacketInspectionNamespace}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "pull-secret", Namespace: dpi.DeepPacketInspectionNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionName, Namespace: dpi.DeepPacketInspectionNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionName, Namespace: dpi.DeepPacketInspectionNamespace}, TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionLinseedRBACName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionLinseedRBACName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraOperatorSecrets, Namespace: dpi.DeepPacketInspectionNamespace}, TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
		}

		rtest.ExpectResources(resources, expectedResources)

		ds := rtest.GetResource(resources, dpi.DeepPacketInspectionName, dpi.DeepPacketInspectionNamespace, "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
		Expect(len(ds.Spec.Template.Spec.Containers)).Should(Equal(1))
		Expect(*ds.Spec.Template.Spec.Containers[0].Resources.Limits.Cpu()).Should(Equal(cpuLimit))
		Expect(*ds.Spec.Template.Spec.Containers[0].Resources.Limits.Memory()).Should(Equal(memoryLimit))
		Expect(ds.Spec.Template.Spec.Containers[0].Resources.Requests.Cpu().IsZero()).Should(BeTrue())
		Expect(ds.Spec.Template.Spec.Containers[0].Resources.Requests.Memory().IsZero()).Should(BeTrue())

		validateDPIComponents(resources, true)
	})

	It("should delete resources for deep packet inspection if there is no valid product license", func() {
		cfg.HasNoLicense = true
		component := dpi.DPI(cfg)

		createResources, deleteResource := component.Objects()
		expectedResources := []resourceTestObj{
			{name: dpi.DeepPacketInspectionNamespace, ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: relasticsearch.PublicCertSecret, ns: dpi.DeepPacketInspectionNamespace, group: "", version: "v1", kind: "Secret"},
			{name: dpi.DeepPacketInspectionPolicyName, ns: dpi.DeepPacketInspectionNamespace, group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
			{name: "pull-secret", ns: dpi.DeepPacketInspectionNamespace, group: "", version: "v1", kind: "Secret"},
			{name: dpi.DeepPacketInspectionName, ns: dpi.DeepPacketInspectionNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: dpi.DeepPacketInspectionName, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: dpi.DeepPacketInspectionName, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: dpi.DeepPacketInspectionName, ns: dpi.DeepPacketInspectionNamespace, group: "apps", version: "v1", kind: "DaemonSet"},
			{name: dpi.DeepPacketInspectionLinseedRBACName, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: dpi.DeepPacketInspectionLinseedRBACName, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-linseed", ns: "tigera-dpi", group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
		}

		Expect(len(deleteResource)).To(Equal(len(expectedResources)))
		Expect(len(createResources)).To(Equal(0))

		for i, expectedRes := range expectedResources {
			rtest.ExpectResourceTypeAndObjectMetadata(deleteResource[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}
	})

	It("should delete resources for deep packet inspection for a managed cluster if there is no DPI resource", func() {
		cfg = &dpi.DPIConfig{
			IntrusionDetection: ids,
			Installation:       installation,
			TyphaNodeTLS:       typhaNodeTLS,
			PullSecrets:        pullSecrets,
			OpenShift:          false,
			HasNoLicense:       false,
			HasNoDPIResource:   true,
			ManagedCluster:     true,
			ClusterDomain:      dns.DefaultClusterDomain,
			DPICertSecret:      dpiCertSecret,
		}
		component := dpi.DPI(cfg)
		createResources, deleteResource := component.Objects()

		expectedDeleteResources := []client.Object{
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionPolicyName, Namespace: dpi.DeepPacketInspectionNamespace}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: relasticsearch.PublicCertSecret, Namespace: dpi.DeepPacketInspectionNamespace}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "pull-secret", Namespace: dpi.DeepPacketInspectionNamespace}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionNamespace, Namespace: dpi.DeepPacketInspectionNamespace}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionName}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionNamespace}},
			&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionName, Namespace: dpi.DeepPacketInspectionNamespace}, TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionLinseedRBACName}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionLinseedRBACName}},
		}
		rtest.ExpectResources(deleteResource, expectedDeleteResources)

		expectedCreateResources := []client.Object{
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionName}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-linseed", Namespace: dpi.DeepPacketInspectionNamespace}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraOperatorSecrets, Namespace: dpi.DeepPacketInspectionNamespace}, TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
		}
		rtest.ExpectResources(createResources, expectedCreateResources)
	})

	It("should delete resources for deep packet inspection for a management cluster if there is no DPI resource", func() {
		cfg = &dpi.DPIConfig{
			IntrusionDetection: ids,
			Installation:       installation,
			TyphaNodeTLS:       typhaNodeTLS,
			PullSecrets:        pullSecrets,
			OpenShift:          false,
			HasNoLicense:       false,
			HasNoDPIResource:   true,
			ManagementCluster:  true,
			ClusterDomain:      dns.DefaultClusterDomain,
			DPICertSecret:      dpiCertSecret,
		}
		component := dpi.DPI(cfg)
		createResources, deleteResource := component.Objects()

		expectedDeleteResources := []client.Object{
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionPolicyName, Namespace: dpi.DeepPacketInspectionNamespace}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: relasticsearch.PublicCertSecret, Namespace: dpi.DeepPacketInspectionNamespace}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "pull-secret", Namespace: dpi.DeepPacketInspectionNamespace}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionNamespace, Namespace: dpi.DeepPacketInspectionNamespace}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionName}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionNamespace}},
			&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionName, Namespace: dpi.DeepPacketInspectionNamespace}, TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-linseed", Namespace: dpi.DeepPacketInspectionNamespace}},
		}
		rtest.ExpectResources(deleteResource, expectedDeleteResources)

		expectedCreateResources := []client.Object{
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionName}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionLinseedRBACName}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionLinseedRBACName}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraOperatorSecrets, Namespace: dpi.DeepPacketInspectionNamespace}, TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
		}
		rtest.ExpectResources(createResources, expectedCreateResources)
	})

	It("should delete resources for deep packet inspection if there is no DPI resource", func() {
		cfg.HasNoDPIResource = true
		component := dpi.DPI(cfg)
		createResources, deleteResource := component.Objects()
		expectedResources := []client.Object{
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: relasticsearch.PublicCertSecret, Namespace: dpi.DeepPacketInspectionNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}},
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionPolicyName, Namespace: dpi.DeepPacketInspectionNamespace}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "pull-secret", Namespace: dpi.DeepPacketInspectionNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionName, Namespace: dpi.DeepPacketInspectionNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionName, Namespace: dpi.DeepPacketInspectionNamespace}, TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionLinseedRBACName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionLinseedRBACName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-linseed", Namespace: "tigera-dpi"}, TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
		}

		expectedCreateResources := []client.Object{
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraOperatorSecrets, Namespace: dpi.DeepPacketInspectionNamespace}, TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
		}
		rtest.ExpectResources(deleteResource, expectedResources)
		rtest.ExpectResources(createResources, expectedCreateResources)
	})

	It("should render SecurityContextConstrains properly when provider is OpenShift", func() {
		cfg.Installation.KubernetesProvider = operatorv1.ProviderOpenShift
		cfg.OpenShift = true
		component := dpi.DPI(cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		role := rtest.GetResource(resources, "tigera-dpi", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(role.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups:     []string{"security.openshift.io"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
			ResourceNames: []string{"privileged"},
		}))
	})

	Context("calico-system rendering", func() {
		policyName := types.NamespacedName{Name: "calico-system.tigera-dpi", Namespace: "tigera-dpi"}

		getExpectedPolicy := func(scenario testutils.CalicoSystemScenario) *v3.NetworkPolicy {
			return testutils.SelectPolicyByClusterTypeAndProvider(
				scenario,
				map[string]*v3.NetworkPolicy{
					"unmanaged":           expectedUnmanagedPolicy,
					"unmanaged-openshift": expectedUnmanagedPolicyForOpenshift,
					"managed":             expectedManagedPolicy,
					"managed-openshift":   expectedManagedPolicyForOpenshift,
				},
			)
		}

		DescribeTable("should render calico-system policy",
			func(scenario testutils.CalicoSystemScenario) {
				cfg.ManagedCluster = scenario.ManagedCluster
				cfg.OpenShift = scenario.OpenShift
				component := dpi.DPI(cfg)
				resources, _ := component.Objects()

				policy := testutils.GetCalicoSystemPolicyFromResources(policyName, resources)
				expectedPolicy := getExpectedPolicy(scenario)
				Expect(policy).To(Equal(expectedPolicy))
			},
			Entry("for management/standalone, kube-dns", testutils.CalicoSystemScenario{ManagedCluster: false, OpenShift: false}),
			Entry("for management/standalone, openshift-dns", testutils.CalicoSystemScenario{ManagedCluster: false, OpenShift: true}),
			Entry("for managed, kube-dns", testutils.CalicoSystemScenario{ManagedCluster: true, OpenShift: false}),
			Entry("for managed, openshift-dns", testutils.CalicoSystemScenario{ManagedCluster: true, OpenShift: true}),
		)
	})

	Context("with DPI init container configured", func() {
		BeforeEach(func() {
			ids.Spec.DeepPacketInspectionDaemonset = &operatorv1.DeepPacketInspectionDaemonset{
				Spec: &operatorv1.DPIDaemonsetSpec{
					Template: &operatorv1.DPIDaemonsetTemplate{
						Spec: &operatorv1.DPIDaemonsetTemplateSpec{
							InitContainers: []operatorv1.DPIDaemonsetInitContainer{
								{
									Name:  "snort-rules",
									Image: "gcr.io/blah/snort-rules:rev01",
								},
							},
						},
					},
				},
			}
		})

		AfterEach(func() {
			ids.Spec.DeepPacketInspectionDaemonset = nil
		})

		It("should render all other DPI resources unchanged when the DPI init container is configured", func() {
			component := dpi.DPI(cfg)

			resources, _ := component.Objects()

			expectedResources := []client.Object{
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"}},
				&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionPolicyName, Namespace: dpi.DeepPacketInspectionNamespace}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "pull-secret", Namespace: dpi.DeepPacketInspectionNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}},
				&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionName, Namespace: dpi.DeepPacketInspectionNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
				&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
				&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
				&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionName, Namespace: dpi.DeepPacketInspectionNamespace}, TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"}},
				&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionLinseedRBACName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
				&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: dpi.DeepPacketInspectionLinseedRBACName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
				&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraOperatorSecrets, Namespace: dpi.DeepPacketInspectionNamespace}, TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			}

			rtest.ExpectResources(resources, expectedResources)

			ds := rtest.GetResource(resources, dpi.DeepPacketInspectionName, dpi.DeepPacketInspectionNamespace, "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
			Expect(ds.Spec.Template.Spec.Containers[0].Env).Should(ContainElements(
				corev1.EnvVar{Name: "LINSEED_CLIENT_CERT", Value: "/deep-packet-inspection-tls/tls.crt"},
				corev1.EnvVar{Name: "LINSEED_CLIENT_KEY", Value: "/deep-packet-inspection-tls/tls.key"},
				corev1.EnvVar{Name: "LINSEED_TOKEN", Value: "/var/run/secrets/kubernetes.io/serviceaccount/token"},
			))
			Expect(len(ds.Spec.Template.Spec.Containers)).Should(Equal(1))
			Expect(*ds.Spec.Template.Spec.Containers[0].Resources.Requests.Cpu()).Should(Equal(resource.MustParse(dpi.DefaultCPURequest)))
			Expect(*ds.Spec.Template.Spec.Containers[0].Resources.Limits.Cpu()).Should(Equal(resource.MustParse(dpi.DefaultCPULimit)))
			Expect(*ds.Spec.Template.Spec.Containers[0].Resources.Requests.Memory()).Should(Equal(resource.MustParse(dpi.DefaultMemoryRequest)))
			Expect(*ds.Spec.Template.Spec.Containers[0].Resources.Limits.Memory()).Should(Equal(resource.MustParse(dpi.DefaultMemoryLimit)))

			validateDPIComponents(resources, false)
		})

		It("should render the DPI Daemonset and the init container for the DPI Daemonset with correct volumes and respective mounts", func() {
			resources, _ := dpi.DPI(cfg).Objects()
			dpiDaemonset := rtest.GetResource(resources, dpi.DeepPacketInspectionName, dpi.DeepPacketInspectionNamespace, "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)

			Expect(dpiDaemonset.Spec.Template.Spec.Volumes).To(ContainElement(
				corev1.Volume{
					Name: "snort-cache",
					VolumeSource: corev1.VolumeSource{
						EmptyDir: &corev1.EmptyDirVolumeSource{},
					},
				},
			))

			Expect(dpiDaemonset.Spec.Template.Spec.Containers[0].VolumeMounts).To(ContainElement(
				corev1.VolumeMount{
					MountPath: "/usr/etc/snort/rules",
					Name:      "snort-cache",
					ReadOnly:  true,
				},
			))

			Expect(len(dpiDaemonset.Spec.Template.Spec.InitContainers)).To(Equal(1))
			Expect(dpiDaemonset.Spec.Template.Spec.InitContainers[0].Name).Should(Equal("snort-rules"))
			Expect(dpiDaemonset.Spec.Template.Spec.InitContainers[0].Image).Should(Equal("gcr.io/blah/snort-rules:rev01"))
			Expect(dpiDaemonset.Spec.Template.Spec.InitContainers[0].VolumeMounts).Should(Equal(
				[]corev1.VolumeMount{
					{
						MountPath: "/usr/etc/snort/rules",
						Name:      "snort-cache",
						ReadOnly:  false,
					},
				},
			))

			validateDPIComponents(resources, false)
		})

		It("should respect custom resource requirements for the DPI init container", func() {
			memoryLimit := resource.MustParse("5Gi")
			cpuLimit := resource.MustParse("5")
			ids.Spec.DeepPacketInspectionDaemonset.Spec.Template.Spec.InitContainers[0].Resources = &corev1.ResourceRequirements{
				Limits: corev1.ResourceList{
					corev1.ResourceMemory: memoryLimit,
					corev1.ResourceCPU:    cpuLimit,
				},
			}

			resources, _ := dpi.DPI(cfg).Objects()
			dpiDaemonset := rtest.GetResource(resources, dpi.DeepPacketInspectionName, dpi.DeepPacketInspectionNamespace, "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
			Expect(len(dpiDaemonset.Spec.Template.Spec.InitContainers)).Should(Equal(1))
			Expect(*dpiDaemonset.Spec.Template.Spec.InitContainers[0].Resources.Limits.Cpu()).Should(Equal(cpuLimit))
			Expect(*dpiDaemonset.Spec.Template.Spec.InitContainers[0].Resources.Limits.Memory()).Should(Equal(memoryLimit))
			Expect(dpiDaemonset.Spec.Template.Spec.InitContainers[0].Resources.Requests.Cpu().IsZero()).Should(BeTrue())
			Expect(dpiDaemonset.Spec.Template.Spec.InitContainers[0].Resources.Requests.Memory().IsZero()).Should(BeTrue())

			validateDPIComponents(resources, false)
		})
	})

	Context("multi-tenant", func() {
		It("should render RBAC to allow Linseed access", func() {
			cfg.Tenant = &operatorv1.Tenant{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tenantA",
					Namespace: "tenantANamespace",
				},
				Spec: operatorv1.TenantSpec{
					ID: "tenant-a-id",
				},
			}
			dpiComponent := dpi.DPI(cfg)

			resources, _ := dpiComponent.Objects()

			cr := rtest.GetResource(resources, dpi.DeepPacketInspectionLinseedRBACName, "", rbacv1.GroupName, "v1", "ClusterRole").(*rbacv1.ClusterRole)
			expectedRules := []rbacv1.PolicyRule{
				{
					APIGroups: []string{"linseed.tigera.io"},
					Resources: []string{"events"},
					Verbs: []string{
						"create",
					},
				},
			}
			Expect(cr.Rules).To(ContainElements(expectedRules))
			rb := rtest.GetResource(resources, dpi.DeepPacketInspectionLinseedRBACName, "", rbacv1.GroupName, "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
			Expect(rb.RoleRef.Kind).To(Equal("ClusterRole"))
			Expect(rb.RoleRef.Name).To(Equal(dpi.DeepPacketInspectionLinseedRBACName))
			Expect(rb.Subjects).To(ContainElements([]rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      dpi.DeepPacketInspectionName,
					Namespace: dpi.DeepPacketInspectionNamespace,
				},
			}))
		})
	})

	Context("LINSEED_URL environment variable", func() {
		It("should set LINSEED_URL correctly for managed cluster", func() {
			managedCfg := &dpi.DPIConfig{
				IntrusionDetection: ids,
				Installation:       installation,
				TyphaNodeTLS:       typhaNodeTLS,
				PullSecrets:        pullSecrets,
				OpenShift:          false,
				HasNoLicense:       false,
				HasNoDPIResource:   false,
				ClusterDomain:      dns.DefaultClusterDomain,
				DPICertSecret:      dpiCertSecret,
				ManagedCluster:     true,
			}
			component := dpi.DPI(managedCfg)
			resources, _ := component.Objects()

			ds := rtest.GetResource(resources, dpi.DeepPacketInspectionName, dpi.DeepPacketInspectionNamespace, "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
			envs := ds.Spec.Template.Spec.Containers[0].Env
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "LINSEED_URL", Value: "https://guardian.calico-system.svc"}))
		})

		It("should set LINSEED_URL correctly for single-tenant standalone cluster", func() {
			standaloneCfg := &dpi.DPIConfig{
				IntrusionDetection: ids,
				Installation:       installation,
				TyphaNodeTLS:       typhaNodeTLS,
				PullSecrets:        pullSecrets,
				OpenShift:          false,
				HasNoLicense:       false,
				HasNoDPIResource:   false,
				ClusterDomain:      dns.DefaultClusterDomain,
				DPICertSecret:      dpiCertSecret,
				ManagedCluster:     false,
				ManagementCluster:  false,
			}
			component := dpi.DPI(standaloneCfg)
			resources, _ := component.Objects()

			ds := rtest.GetResource(resources, dpi.DeepPacketInspectionName, dpi.DeepPacketInspectionNamespace, "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
			envs := ds.Spec.Template.Spec.Containers[0].Env
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "LINSEED_URL", Value: "https://tigera-linseed.tigera-elasticsearch.svc"}))
		})

		It("should set LINSEED_URL correctly for single-tenant management cluster", func() {
			managementCfg := &dpi.DPIConfig{
				IntrusionDetection: ids,
				Installation:       installation,
				TyphaNodeTLS:       typhaNodeTLS,
				PullSecrets:        pullSecrets,
				OpenShift:          false,
				HasNoLicense:       false,
				HasNoDPIResource:   false,
				ClusterDomain:      dns.DefaultClusterDomain,
				DPICertSecret:      dpiCertSecret,
				ManagedCluster:     false,
				ManagementCluster:  true,
			}
			component := dpi.DPI(managementCfg)
			resources, _ := component.Objects()

			ds := rtest.GetResource(resources, dpi.DeepPacketInspectionName, dpi.DeepPacketInspectionNamespace, "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
			envs := ds.Spec.Template.Spec.Containers[0].Env
			Expect(envs).To(ContainElement(corev1.EnvVar{Name: "LINSEED_URL", Value: "https://tigera-linseed.tigera-elasticsearch.svc"}))
		})

		// No need to verify LINSEED_URL for multi-tenant management cluster as a DPI deployment does not get created on the management cluster
		// in a multi-tenant setup. See multi-tenant tests above.
	})
})

func validateDPIComponents(resources []client.Object, openshift bool) {
	dpiNs := rtest.GetResource(resources, dpi.DeepPacketInspectionNamespace, "", "", "v1", "Namespace").(*corev1.Namespace)
	Expect(dpiNs).ShouldNot(BeNil())

	dpiServiceAccount := rtest.GetResource(resources, dpi.DeepPacketInspectionName, dpi.DeepPacketInspectionNamespace, "", "v1", "ServiceAccount").(*corev1.ServiceAccount)
	Expect(dpiServiceAccount).ShouldNot(BeNil())

	dpiClusterRole := rtest.GetResource(resources, dpi.DeepPacketInspectionName, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
	Expect(dpiClusterRole.Rules).Should(ContainElements(expectedClusterRoleRules))

	dpiClusterRoleBinding := rtest.GetResource(resources, dpi.DeepPacketInspectionName, "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
	Expect(dpiClusterRoleBinding.RoleRef).Should(Equal(expectedCRB.RoleRef))
	Expect(dpiClusterRoleBinding.Subjects).Should(BeEquivalentTo(expectedCRB.Subjects))

	dpiDaemonSet := rtest.GetResource(resources, dpi.DeepPacketInspectionName, dpi.DeepPacketInspectionNamespace, "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
	Expect(dpiDaemonSet.Spec.Template.Annotations).To(HaveKey("tigera-operator.hash.operator.tigera.io/tigera-ca-private"))
	Expect(dpiDaemonSet.Spec.Template.Annotations).To(HaveKey("tigera-operator.hash.operator.tigera.io/node-certs"))

	Expect(dpiDaemonSet.Spec.Template.Spec.Volumes).To(ContainElements(expectedVolumes))
	Expect(dpiDaemonSet.Spec.Template.Spec.HostNetwork).Should(BeTrue())
	Expect(dpiDaemonSet.Spec.Template.Spec.NodeSelector).To(BeNil())

	Expect(dpiDaemonSet.Spec.Template.Spec.Containers[0].VolumeMounts).Should(ContainElements(expectedVolumeMounts))
	Expect(*dpiDaemonSet.Spec.Template.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation).To(Equal(openshift))
	Expect(*dpiDaemonSet.Spec.Template.Spec.Containers[0].SecurityContext.Privileged).To(Equal(openshift))
	Expect(*dpiDaemonSet.Spec.Template.Spec.Containers[0].SecurityContext.RunAsGroup).To(BeEquivalentTo(0))
	Expect(*dpiDaemonSet.Spec.Template.Spec.Containers[0].SecurityContext.RunAsNonRoot).To(Equal(false))
	Expect(*dpiDaemonSet.Spec.Template.Spec.Containers[0].SecurityContext.RunAsUser).To(BeEquivalentTo(0))
	Expect(dpiDaemonSet.Spec.Template.Spec.Containers[0].SecurityContext.Capabilities).To(Equal(
		&corev1.Capabilities{
			Drop: []corev1.Capability{"ALL"},
			Add:  []corev1.Capability{"NET_ADMIN", "NET_RAW"},
		},
	))
	Expect(dpiDaemonSet.Spec.Template.Spec.Containers[0].SecurityContext.SeccompProfile).To(Equal(
		&corev1.SeccompProfile{
			Type: corev1.SeccompProfileTypeRuntimeDefault,
		},
	))
}
