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

package render_test

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/authentication"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/testutils"
	"github.com/tigera/operator/pkg/tls"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"github.com/tigera/operator/test"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
)

var _ = Describe("Rendering tests for PacketCapture API component", func() {
	pcPolicyForUnmanaged := testutils.GetExpectedPolicyFromFile("./testutils/expected_policies/packetcapture.json")
	pcPolicyForUnmanagedOCP := testutils.GetExpectedPolicyFromFile("./testutils/expected_policies/packetcapture_ocp.json")
	pcPolicyForManaged := testutils.GetExpectedPolicyFromFile("./testutils/expected_policies/packetcapture_managed.json")
	pcPolicyForManagedOCP := testutils.GetExpectedPolicyFromFile("./testutils/expected_policies/packetcapture_managed_ocp.json")

	var secret certificatemanagement.KeyPairInterface
	var cli client.Client
	BeforeEach(func() {
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

		certificateManager, err := certificatemanager.Create(cli, nil, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())

		secret, err = certificateManager.GetOrCreateKeyPair(cli, render.PacketCaptureServerCert, common.OperatorNamespace(), []string{""})
		Expect(err).NotTo(HaveOccurred())
	})

	// Pull secret
	pullSecrets := []*corev1.Secret{{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pull-secret",
			Namespace: common.OperatorNamespace(),
		},
	}}
	// Installation with minimal setup
	defaultInstallation := operatorv1.InstallationSpec{Variant: operatorv1.CalicoEnterprise}

	// Rendering packet capture resources
	renderPacketCapture := func(i operatorv1.InstallationSpec, config authentication.KeyValidatorConfig) (resources []client.Object) {
		cfg := &render.PacketCaptureApiConfiguration{
			PullSecrets:        pullSecrets,
			Installation:       &i,
			KeyValidatorConfig: config,
			ServerCertSecret:   secret,
			OpenShift:          i.KubernetesProvider.IsOpenShift(),
		}
		pc := render.PacketCaptureAPI(cfg)
		Expect(pc.ResolveImages(nil)).To(BeNil())
		resources, _ = pc.Objects()
		return resources
	}

	// Generate expected resources
	expectedResources := func(useCSR, enableOIDC bool) []client.Object {
		resources := []client.Object{
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: render.PacketCaptureNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "pull-secret", Namespace: render.PacketCaptureNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: render.PacketCaptureServiceAccountName, Namespace: render.PacketCaptureNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: render.PacketCaptureClusterRoleName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.PacketCaptureClusterRoleBindingName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: render.PacketCapturePodExecRoleName, Namespace: common.CalicoNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.PacketCapturePodExecRoleBindingName, Namespace: common.CalicoNamespace}, TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: render.PacketCaptureDeploymentName, Namespace: render.PacketCaptureNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: render.PacketCaptureServiceName, Namespace: render.PacketCaptureNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraOperatorSecrets, Namespace: render.PacketCaptureNamespace}},
		}
		return resources
	}

	// Generate expected environment variables
	expectedEnvVars := func(enableOIDC bool) []corev1.EnvVar {
		envVars := []corev1.EnvVar{
			{Name: "PACKETCAPTURE_API_LOG_LEVEL", Value: "Info"},
			{
				Name:  "PACKETCAPTURE_API_HTTPS_KEY",
				Value: "/tigera-packetcapture-server-tls/tls.key",
			},
			{
				Name:  "PACKETCAPTURE_API_HTTPS_CERT",
				Value: "/tigera-packetcapture-server-tls/tls.crt",
			},
		}

		if enableOIDC {
			envVars = append(envVars, []corev1.EnvVar{
				{
					Name:  "PACKETCAPTURE_API_DEX_ENABLED",
					Value: "true",
				},
				{
					Name:  "PACKETCAPTURE_API_DEX_URL",
					Value: "https://tigera-dex.tigera-dex.svc.cluster.local:5556/",
				},
				{
					Name:  "PACKETCAPTURE_API_OIDC_AUTH_ENABLED",
					Value: "true",
				},
				{
					Name:  "PACKETCAPTURE_API_OIDC_AUTH_ISSUER",
					Value: "https://127.0.0.1/dex",
				},
				{
					Name:  "PACKETCAPTURE_API_OIDC_AUTH_JWKSURL",
					Value: "https://tigera-dex.tigera-dex.svc.cluster.local:5556/dex/keys",
				},
				{
					Name:  "PACKETCAPTURE_API_OIDC_AUTH_CLIENT_ID",
					Value: "tigera-manager",
				},
				{
					Name:  "PACKETCAPTURE_API_OIDC_AUTH_USERNAME_CLAIM",
					Value: "email",
				},
				{
					Name:  "PACKETCAPTURE_API_OIDC_AUTH_GROUPS_CLAIM",
					Value: "groups",
				},
				{
					Name:  "PACKETCAPTURE_API_OIDC_AUTH_USERNAME_PREFIX",
					Value: "",
				},
				{
					Name:  "PACKETCAPTURE_API_OIDC_AUTH_GROUPS_PREFIX",
					Value: "",
				},
			}...)
		}

		return envVars
	}

	// Generate expected volume mounts
	expectedVolumeMounts := func() []corev1.VolumeMount {
		volumeMounts := []corev1.VolumeMount{
			{
				Name:      render.PacketCaptureServerCert,
				MountPath: "/tigera-packetcapture-server-tls",
				ReadOnly:  true,
			},
		}
		return volumeMounts
	}
	// Generate expected containers
	expectedContainers := func(enableOIDC bool) []corev1.Container {
		volumeMounts := expectedVolumeMounts()
		envVars := expectedEnvVars(enableOIDC)

		return []corev1.Container{
			{
				Name:    render.PacketCaptureContainerName,
				Image:   fmt.Sprintf("%s%s%s:%s", components.TigeraRegistry, components.TigeraImagePath, components.ComponentTigeraCalico.Image, components.ComponentTigeraCalico.Version),
				Command: []string{components.CalicoBinaryPath, "component", "packetcapture"},
				SecurityContext: &corev1.SecurityContext{
					AllowPrivilegeEscalation: ptr.To(false),
					Capabilities: &corev1.Capabilities{
						Drop: []corev1.Capability{"ALL"},
					},
					Privileged:   ptr.To(false),
					RunAsGroup:   ptr.To(int64(10001)),
					RunAsNonRoot: ptr.To(true),
					RunAsUser:    ptr.To(int64(10001)),
					SeccompProfile: &corev1.SeccompProfile{
						Type: corev1.SeccompProfileTypeRuntimeDefault,
					},
				},
				ReadinessProbe: &corev1.Probe{
					ProbeHandler: corev1.ProbeHandler{
						HTTPGet: &corev1.HTTPGetAction{
							Path:   "/health",
							Port:   intstr.FromInt(8444),
							Scheme: corev1.URISchemeHTTPS,
						},
					},
					InitialDelaySeconds: 30,
				},
				LivenessProbe: &corev1.Probe{
					ProbeHandler: corev1.ProbeHandler{
						HTTPGet: &corev1.HTTPGetAction{
							Path:   "/health",
							Port:   intstr.FromInt(8444),
							Scheme: corev1.URISchemeHTTPS,
						},
					},
					InitialDelaySeconds: 30,
				},
				Env:          envVars,
				VolumeMounts: volumeMounts,
			},
		}
	}

	// Generate expected volumes
	expectedVolumes := func(useCSR bool) []corev1.Volume {
		var volumes []corev1.Volume
		if useCSR {
			volumes = append(volumes, corev1.Volume{
				Name: render.PacketCaptureServerCert,
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{
						Medium: corev1.StorageMediumMemory,
					},
				},
			})
		} else {
			volumes = append(volumes, corev1.Volume{
				Name: render.PacketCaptureServerCert,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName:  render.PacketCaptureServerCert,
						DefaultMode: ptr.To(int32(420)),
					},
				},
			})
		}

		return volumes
	}

	checkPacketCaptureResources := func(resources []client.Object, useCSR, enableOIDC bool) {
		expectedResources := expectedResources(useCSR, enableOIDC)

		rtest.ExpectResources(resources, expectedResources)

		// Check the namespace.
		namespace := rtest.GetResource(resources, render.PacketCaptureNamespace, "", "", "v1", "Namespace").(*corev1.Namespace)
		Expect(namespace.Labels["pod-security.kubernetes.io/enforce"]).To(Equal("restricted"))
		Expect(namespace.Labels["pod-security.kubernetes.io/enforce-version"]).To(Equal("latest"))

		// Check deployment
		deployment := rtest.GetResource(resources, render.PacketCaptureDeploymentName, render.PacketCaptureNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(deployment).NotTo(BeNil())

		// Check containers
		Expect(deployment.Spec.Template.Spec.Containers).To(ConsistOf(expectedContainers(enableOIDC)))

		// Check init containers
		if useCSR {
			Expect(len(deployment.Spec.Template.Spec.InitContainers)).To(Equal(1))
			Expect(deployment.Spec.Template.Spec.InitContainers[0].Name).To(Equal(fmt.Sprintf("%s-key-cert-provisioner", render.PacketCaptureServerCert)))
		}

		// Check volumes
		Expect(deployment.Spec.Template.Spec.Volumes).To(ConsistOf(expectedVolumes(useCSR)))

		// Check annotations
		if !useCSR {
			Expect(deployment.Spec.Template.Annotations).To(HaveKeyWithValue("tigera-operator.hash.operator.tigera.io/tigera-packetcapture-server-tls", Not(BeEmpty())))
		}

		// Check permissions
		clusterRole := rtest.GetResource(resources, render.PacketCaptureClusterRoleName, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(clusterRole.Rules).To(ConsistOf([]rbacv1.PolicyRule{
			{
				APIGroups: []string{"authorization.k8s.io"},
				Resources: []string{"subjectaccessreviews"},
				Verbs:     []string{"create"},
			},
			{
				APIGroups: []string{"authentication.k8s.io"},
				Resources: []string{"tokenreviews"},
				Verbs:     []string{"create"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"packetcaptures"},
				Verbs:     []string{"get"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"packetcaptures/status"},
				Verbs:     []string{"update"},
			},
		}))
		clusterRoleBinding := rtest.GetResource(resources, render.PacketCaptureClusterRoleBindingName, "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
		Expect(clusterRoleBinding.RoleRef.Name).To(Equal(render.PacketCaptureClusterRoleName))
		Expect(clusterRoleBinding.Subjects).To(ConsistOf([]rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      render.PacketCaptureServiceAccountName,
				Namespace: render.PacketCaptureNamespace,
			},
		}))

		// The pod/exec Role lets the PacketCapture API read capture files off the
		// per-node calico-node pod; it is namespaced to calico-system.
		podExecRole := rtest.GetResource(resources, render.PacketCapturePodExecRoleName, common.CalicoNamespace, "rbac.authorization.k8s.io", "v1", "Role").(*rbacv1.Role)
		Expect(podExecRole.Rules).To(ConsistOf([]rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods/exec"},
				Verbs:     []string{"create"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"list"},
			},
		}))
		podExecRoleBinding := rtest.GetResource(resources, render.PacketCapturePodExecRoleBindingName, common.CalicoNamespace, "rbac.authorization.k8s.io", "v1", "RoleBinding").(*rbacv1.RoleBinding)
		Expect(podExecRoleBinding.RoleRef.Name).To(Equal(render.PacketCapturePodExecRoleName))
		Expect(podExecRoleBinding.Subjects).To(ConsistOf([]rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      render.PacketCaptureServiceAccountName,
				Namespace: render.PacketCaptureNamespace,
			},
		}))

		// Check service
		service := rtest.GetResource(resources, render.PacketCaptureServiceName, render.PacketCaptureNamespace, "", "v1", "Service").(*corev1.Service)
		Expect(service.Spec.Ports).To(ConsistOf([]corev1.ServicePort{
			{
				Name:       render.PacketCaptureName,
				Port:       443,
				Protocol:   corev1.ProtocolTCP,
				TargetPort: intstr.FromInt(8444),
			},
		}))
	}

	It("should render all resources for default installation", func() {
		resources := renderPacketCapture(defaultInstallation, nil)

		checkPacketCaptureResources(resources, false, false)
	})

	It("should render controlPlaneTolerations", func() {
		t := corev1.Toleration{
			Key:      "foo",
			Operator: corev1.TolerationOpEqual,
			Value:    "bar",
		}
		resources := renderPacketCapture(operatorv1.InstallationSpec{
			Variant:                 operatorv1.CalicoEnterprise,
			ControlPlaneTolerations: []corev1.Toleration{t},
		}, nil)

		checkPacketCaptureResources(resources, false, false)

		deployment := rtest.GetResource(resources, render.PacketCaptureDeploymentName, render.PacketCaptureNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(deployment).NotTo(BeNil())
		Expect(deployment.Spec.Template.Spec.Tolerations).Should(ContainElements(append(rmeta.TolerateCriticalAddonsAndControlPlane, t)))
	})

	It("should render toleration on GKE", func() {
		resources := renderPacketCapture(operatorv1.InstallationSpec{
			Variant:            operatorv1.CalicoEnterprise,
			KubernetesProvider: operatorv1.ProviderGKE,
		}, nil)
		deployment := rtest.GetResource(resources, render.PacketCaptureDeploymentName, render.PacketCaptureNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(deployment).NotTo(BeNil())
		Expect(deployment.Spec.Template.Spec.Tolerations).To(ContainElements(corev1.Toleration{
			Key:      "kubernetes.io/arch",
			Operator: corev1.TolerationOpEqual,
			Value:    "arm64",
			Effect:   corev1.TaintEffectNoSchedule,
		}))
	})

	It("should render SecurityContextConstrains properly when provider is OpenShift", func() {
		resources := renderPacketCapture(operatorv1.InstallationSpec{
			Variant:            operatorv1.CalicoEnterprise,
			KubernetesProvider: operatorv1.ProviderOpenShift,
		}, nil)

		role := rtest.GetResource(resources, "tigera-packetcapture", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(role.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups:     []string{"security.openshift.io"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
			ResourceNames: []string{"nonroot-v2"},
		}))
	})

	It("should render all resources for an installation with certificate management", func() {
		ca, _ := tls.MakeCA(rmeta.DefaultOperatorCASignerName())
		cert, _, _ := ca.Config.GetPEMBytes() // create a valid pem block
		installation := operatorv1.InstallationSpec{Variant: operatorv1.CalicoEnterprise, CertificateManagement: &operatorv1.CertificateManagement{CACert: cert}}

		certificateManager, err := certificatemanager.Create(cli, &installation, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())

		secret, err = certificateManager.GetOrCreateKeyPair(cli, render.PacketCaptureServerCert, common.OperatorNamespace(), []string{""})
		Expect(err).NotTo(HaveOccurred())

		resources := renderPacketCapture(installation, nil)
		checkPacketCaptureResources(resources, true, false)
	})

	It("should render all resources for an installation with oidc configured", func() {
		authentication := &operatorv1.Authentication{
			Spec: operatorv1.AuthenticationSpec{
				ManagerDomain: "https://127.0.0.1",
				OIDC:          &operatorv1.AuthenticationOIDC{IssuerURL: "https://accounts.google.com", UsernameClaim: "email"},
			},
		}

		dexCfg := render.NewDexKeyValidatorConfig(authentication, dns.DefaultClusterDomain)
		resources := renderPacketCapture(defaultInstallation, dexCfg)

		checkPacketCaptureResources(resources, false, true)
	})

	Context("calico-system rendering", func() {
		policyName := types.NamespacedName{Name: "calico-system.tigera-packetcapture", Namespace: "tigera-packetcapture"}

		DescribeTable("should render calico-system policy",
			func(scenario testutils.CalicoSystemScenario) {
				cfg := &render.PacketCaptureApiConfiguration{
					PullSecrets:      pullSecrets,
					Installation:     &defaultInstallation,
					ServerCertSecret: secret,
				}
				cfg.OpenShift = scenario.OpenShift
				if scenario.ManagedCluster {
					cfg.ManagementClusterConnection = &operatorv1.ManagementClusterConnection{}
				} else {
					cfg.ManagementClusterConnection = nil
				}

				component := render.PacketCaptureAPIPolicy(cfg)
				resources, _ := component.Objects()

				policy := testutils.GetCalicoSystemPolicyFromResources(policyName, resources)
				expectedPolicy := testutils.SelectPolicyByClusterTypeAndProvider(
					scenario,
					map[string]*v3.NetworkPolicy{
						"unmanaged":           pcPolicyForUnmanaged,
						"unmanaged-openshift": pcPolicyForUnmanagedOCP,
						"managed":             pcPolicyForManaged,
						"managed-openshift":   pcPolicyForManagedOCP,
					},
				)
				Expect(policy).To(Equal(expectedPolicy))
			},
			Entry("for management/standalone, kube-dns", testutils.CalicoSystemScenario{ManagedCluster: false, OpenShift: false}),
			Entry("for management/standalone, openshift-dns", testutils.CalicoSystemScenario{ManagedCluster: false, OpenShift: true}),
			Entry("for managed, kube-dns", testutils.CalicoSystemScenario{ManagedCluster: true, OpenShift: false}),
			Entry("for managed, openshift-dns", testutils.CalicoSystemScenario{ManagedCluster: true, OpenShift: true}),
		)
	})

	Context("reconcile resource requirements", func() {
		It("should override container's resource request and render init container with default values", func() {
			ca, _ := tls.MakeCA(rmeta.DefaultOperatorCASignerName())
			cert, _, _ := ca.Config.GetPEMBytes() // create a valid pem block
			installation := operatorv1.InstallationSpec{Variant: operatorv1.CalicoEnterprise, CertificateManagement: &operatorv1.CertificateManagement{CACert: cert}}

			certificateManager, err := certificatemanager.Create(cli, &installation, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
			Expect(err).NotTo(HaveOccurred())

			secret, err = certificateManager.GetOrCreateKeyPair(cli, render.PacketCaptureServerCert, common.OperatorNamespace(), []string{""})
			Expect(err).NotTo(HaveOccurred())

			cfg := &render.PacketCaptureApiConfiguration{
				PullSecrets:      pullSecrets,
				Installation:     &installation,
				ServerCertSecret: secret,
			}

			pcResources := corev1.ResourceRequirements{
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

			packetCaptureAPICfg := &operatorv1.PacketCaptureAPI{
				Spec: operatorv1.PacketCaptureAPISpec{
					PacketCaptureAPIDeployment: &operatorv1.PacketCaptureAPIDeployment{
						Spec: &operatorv1.PacketCaptureAPIDeploymentSpec{
							Template: &operatorv1.PacketCaptureAPIDeploymentPodTemplateSpec{
								Spec: &operatorv1.PacketCaptureAPIDeploymentPodSpec{
									Containers: []operatorv1.PacketCaptureAPIDeploymentContainer{{
										Name:      "tigera-packetcapture-server",
										Resources: &pcResources,
									}},
								},
							},
						},
					},
				},
			}

			cfg.PacketCaptureAPI = packetCaptureAPICfg
			component := render.PacketCaptureAPI(cfg)
			resources, _ := component.Objects()

			d, ok := rtest.GetResource(resources, "tigera-packetcapture", render.PacketCaptureNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue())

			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))

			container := test.GetContainer(d.Spec.Template.Spec.Containers, "tigera-packetcapture-server")
			Expect(container).NotTo(BeNil())
			Expect(container.Resources).To(Equal(pcResources))

			initContainer := test.GetContainer(d.Spec.Template.Spec.InitContainers, "tigera-packetcapture-server-tls-key-cert-provisioner")
			Expect(initContainer).NotTo(BeNil())
			Expect(initContainer.Resources).To(Equal(corev1.ResourceRequirements{
				Limits: corev1.ResourceList{
					"cpu":    resource.MustParse("10m"),
					"memory": resource.MustParse("50Mi"),
				},
				Requests: corev1.ResourceList{
					"cpu":    resource.MustParse("10m"),
					"memory": resource.MustParse("50Mi"),
				},
			}))
		})
	})
})
