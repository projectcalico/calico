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
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"gopkg.in/yaml.v2"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	csisecret "sigs.k8s.io/secrets-store-csi-driver/apis/v1"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/podaffinity"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/testutils"
	"github.com/tigera/operator/pkg/tls"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"github.com/tigera/operator/test"
)

var _ = Describe("dex rendering tests", func() {
	const clusterName = "svc.cluster.local"
	var cli client.Client

	expectedDexPolicy := testutils.GetExpectedPolicyFromFile("testutils/expected_policies/dex.json")
	expectedDexOpenshiftPolicy := testutils.GetExpectedPolicyFromFile("testutils/expected_policies/dex_ocp.json")

	Context("dex is configured for oidc", func() {
		const (
			rbac           = "rbac.authorization.k8s.io"
			pullSecretName = "tigera-pull-secret"
		)

		var (
			authentication *operatorv1.Authentication
			idpSecret      *corev1.Secret
			pullSecrets    []*corev1.Secret
			replicas       int32
			cfg            *render.DexComponentConfiguration
		)

		expectedVolumeMounts := []corev1.VolumeMount{
			{Name: "config", MountPath: "/etc/dex/baseCfg", ReadOnly: true},
			{Name: "secrets", MountPath: "/etc/dex/secrets", ReadOnly: true},
			{Name: "tigera-dex-tls", MountPath: "/tigera-dex-tls", ReadOnly: true},
			{Name: "tigera-ca-bundle", MountPath: "/etc/pki/tls/certs", ReadOnly: true},
			{Name: "tigera-ca-bundle", MountPath: "/etc/pki/tls/cert.pem", SubPath: "ca-bundle.crt", ReadOnly: true},
		}

		expectedVolumes := []corev1.Volume{
			{
				Name: "config",
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: "tigera-dex",
						},
						Items: []corev1.KeyToPath{
							{Key: "config.yaml", Path: "config.yaml"},
						},
					},
				},
			},
			{
				Name: "secrets",
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: "tigera-oidc-credentials",
						Items: []corev1.KeyToPath{
							{Key: "serviceAccountSecret", Path: "google-groups.json"},
						},
						DefaultMode: ptr.To(int32(420)),
					},
				},
			},
			{
				Name: "tigera-dex-tls",
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName:  "tigera-dex-tls",
						DefaultMode: ptr.To(int32(420)),
					},
				},
			},
			{
				Name: "tigera-ca-bundle",
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: "tigera-ca-bundle",
						},
						Items: []corev1.KeyToPath{
							{Key: certificatemanagement.TrustedCertConfigMapKeyName, Path: certificatemanagement.TrustedCertConfigMapKeyName},
							//nolint:staticcheck // Ignore SA1019 deprecated
							{Key: certificatemanagement.TrustedCertConfigMapKeyName, Path: certificatemanagement.LegacyTrustedCertConfigMapKeyName},
							{Key: certificatemanagement.TrustedCertConfigMapKeyName, Path: "ca.pem"},
							{Key: certificatemanagement.RHELRootCertificateBundleName, Path: certificatemanagement.RHELRootCertificateBundleName},
						},
					},
				},
			},
		}

		BeforeEach(func() {
			scheme := runtime.NewScheme()
			Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
			cli = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

			certificateManager, err := certificatemanager.Create(cli, nil, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
			Expect(err).NotTo(HaveOccurred())

			dnsNames := dns.GetServiceDNSNames(render.DexObjectName, render.DexNamespace, clusterDomain)
			tlsKeyPair, err := certificateManager.GetOrCreateKeyPair(cli, render.DexTLSSecretName, common.OperatorNamespace(), dnsNames)
			Expect(err).NotTo(HaveOccurred())
			installation := &operatorv1.InstallationSpec{
				ControlPlaneReplicas: &replicas,
				KubernetesProvider:   operatorv1.ProviderNone,
			}

			authentication = &operatorv1.Authentication{
				Spec: operatorv1.AuthenticationSpec{
					ManagerDomain: "https://example.com",
					OIDC: &operatorv1.AuthenticationOIDC{
						IssuerURL:       "https://example.com",
						UsernameClaim:   "email",
						GroupsClaim:     "group",
						RequestedScopes: []string{"scope"},
					},
				},
			}

			idpSecret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.OIDCSecretName,
					Namespace: common.OperatorNamespace(),
				},
				TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
				Data: map[string][]byte{
					"adminEmail":           []byte("a@b.com"),
					"clientID":             []byte("a.b.com"),
					"clientSecret":         []byte("my-secret"),
					"serviceAccountSecret": []byte("my-secret2"),
				},
			}
			pullSecrets = []*corev1.Secret{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      pullSecretName,
						Namespace: common.OperatorNamespace(),
					},
					TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
				},
			}

			replicas = 2

			dexCfg := render.NewDexConfig(installation.CertificateManagement, authentication, idpSecret, nil, clusterName)
			trustedCaBundle, err := certificateManager.CreateTrustedBundleWithSystemRootCertificates()
			Expect(err).NotTo(HaveOccurred())

			cfg = &render.DexComponentConfiguration{
				PullSecrets:   pullSecrets,
				Installation:  installation,
				DexConfig:     dexCfg,
				ClusterDomain: clusterName,
				TLSKeyPair:    tlsKeyPair,
				TrustedBundle: trustedCaBundle,
			}
		})

		It("should render all resources for a OIDC setup", func() {
			component := render.Dex(cfg)
			resources, _ := component.Objects()

			expectedResources := []client.Object{
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: render.DexObjectName}, TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"}},
				&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: render.DexPolicyName, Namespace: render.DexNamespace}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
				&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: networkpolicy.CalicoComponentDefaultDenyPolicyName, Namespace: render.DexNamespace}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
				&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: render.DexObjectName, Namespace: render.DexNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
				&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: render.DexObjectName, Namespace: render.DexNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"}},
				&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: render.DexObjectName, Namespace: render.DexNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},
				&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: render.DexObjectName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
				&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.DexObjectName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
				&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: render.DexObjectName, Namespace: render.DexNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.OIDCSecretName, Namespace: common.OperatorNamespace()}, TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.OIDCSecretName, Namespace: render.DexNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: pullSecretName, Namespace: render.DexNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}},
				&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraOperatorSecrets, Namespace: render.DexNamespace}},
			}

			rtest.ExpectResources(resources, expectedResources)

			d := rtest.GetResource(resources, "tigera-dex", "tigera-dex", "apps", "v1", "Deployment").(*appsv1.Deployment)

			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
			Expect(*d.Spec.Template.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
			Expect(*d.Spec.Template.Spec.Containers[0].SecurityContext.Privileged).To(BeFalse())
			Expect(*d.Spec.Template.Spec.Containers[0].SecurityContext.RunAsGroup).To(BeEquivalentTo(10001))
			Expect(*d.Spec.Template.Spec.Containers[0].SecurityContext.RunAsNonRoot).To(BeTrue())
			Expect(*d.Spec.Template.Spec.Containers[0].SecurityContext.RunAsUser).To(BeEquivalentTo(10001))
			Expect(d.Spec.Template.Spec.Containers[0].SecurityContext.Capabilities).To(Equal(
				&corev1.Capabilities{
					Drop: []corev1.Capability{"ALL"},
				},
			))
			Expect(d.Spec.Template.Spec.Containers[0].SecurityContext.SeccompProfile).To(Equal(
				&corev1.SeccompProfile{
					Type: corev1.SeccompProfileTypeRuntimeDefault,
				}))

			for k, v := range cfg.TrustedBundle.HashAnnotations() {
				Expect(d.Spec.Template.Annotations).To(HaveKeyWithValue(k, v))
			}
			Expect(d.Spec.Template.Spec.Containers[0].VolumeMounts).To(BeEquivalentTo(expectedVolumeMounts))
			Expect(d.Spec.Template.Spec.Volumes).To(BeEquivalentTo(expectedVolumes))
			cm, ok := rtest.GetResource(resources, "tigera-dex", "tigera-dex", "", "v1", "ConfigMap").(*corev1.ConfigMap)
			Expect(ok).To(BeTrue())
			var config ConfigYAML
			// Decode the JSON string into an object into a ConfigYAML object, which allows easier introspection.
			err := yaml.Unmarshal([]byte(cm.Data["config.yaml"]), &config)
			Expect(err).NotTo(HaveOccurred())
			Expect(config.Expiry.IDTokens).To(Equal("15m"))
			Expect(config.StaticClients).To(HaveLen(1))
			Expect(config.StaticClients[0].RedirectURIs).To(ConsistOf(
				"https://localhost:9443/login/oidc/callback",
				"https://localhost:9443/login/oidc/silent-callback",
				"https://127.0.0.1:9443/login/oidc/callback",
				"https://127.0.0.1:9443/login/oidc/silent-callback",
				"https://example.com/login/oidc/callback",
				"https://example.com/login/oidc/silent-callback"))
		})

		It("should render config Map with the HSTS headers", func() {
			component := render.Dex(cfg)
			resources, _ := component.Objects()

			d := rtest.GetResource(resources, "tigera-dex", "tigera-dex", "apps", "v1", "Deployment").(*appsv1.Deployment)

			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
			Expect(d.Spec.Template.Spec.Containers[0].VolumeMounts).To(BeEquivalentTo(expectedVolumeMounts))
			Expect(d.Spec.Template.Spec.Volumes).To(BeEquivalentTo(expectedVolumes))

			cm, ok := rtest.GetResource(resources, "tigera-dex", "tigera-dex", "", "v1", "ConfigMap").(*corev1.ConfigMap)
			Expect(ok).To(BeTrue())
			var config ConfigYAML
			// Decode the JSON string into an object into a ConfigYAML object, which allows easier introspection.
			err := yaml.Unmarshal([]byte(cm.Data["config.yaml"]), &config)
			Expect(err).NotTo(HaveOccurred())
			Expect(config.Web.Headers.ContentSecurityPolicy).To(Equal(""))
			Expect(config.Web.Headers.XXSSProtection).To(Equal("1; mode=block"))
			Expect(config.Web.Headers.XFrameOptions).To(Equal("SAMEORIGIN"))
			Expect(config.Web.Headers.StrictTransportSecurity).To(Equal("max-age=31536000; includeSubDomains"))
			Expect(config.Web.Headers.XContentTypeOptions).To(Equal("nosniff"))
		})

		DescribeTable("should render the cluster name properly in the validator", func(clusterDomain string) {
			validatorConfig := render.NewDexKeyValidatorConfig(authentication, clusterDomain)
			validatorEnv := validatorConfig.RequiredEnv("")

			expectedUrl := fmt.Sprintf("https://tigera-dex.tigera-dex.svc.%s:5556", clusterDomain)
			Expect(validatorEnv[1].Value).To(Equal(expectedUrl + "/"))
			Expect(validatorEnv[4].Value).To(Equal(expectedUrl + "/dex/keys"))
		},
			Entry("default cluster domain", dns.DefaultClusterDomain),
			Entry("custom cluster domain", "custom.internal"),
		)

		Context("when SecretProviderClass is provided", func() {
			var secretProviderClass *csisecret.SecretProviderClass

			BeforeEach(func() {
				secretProviderClass = &csisecret.SecretProviderClass{
					TypeMeta:   metav1.TypeMeta{Kind: "SecretProviderClass", APIVersion: "secrets-store.csi.x-k8s.io/v1"},
					ObjectMeta: metav1.ObjectMeta{Name: render.OIDCSecretName, Namespace: common.OperatorNamespace()},
				}
				cfg.DexConfig = render.NewDexConfig(cfg.Installation.CertificateManagement, authentication, nil, secretProviderClass, clusterName)
				cfg.Authentication = authentication
			})

			It("should render resources using SecretProviderClass", func() {
				component := render.Dex(cfg)
				resources, _ := component.Objects()

				expectedResources := []client.Object{
					&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: render.DexObjectName}, TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"}},
					&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: render.DexPolicyName, Namespace: render.DexNamespace}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
					&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: networkpolicy.CalicoComponentDefaultDenyPolicyName, Namespace: render.DexNamespace}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
					&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: render.DexObjectName, Namespace: render.DexNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
					&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: render.DexObjectName, Namespace: render.DexNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"}},
					&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: render.DexObjectName, Namespace: render.DexNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},
					&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: render.DexObjectName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
					&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.DexObjectName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
					&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: render.DexObjectName, Namespace: render.DexNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}},
					&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: pullSecretName, Namespace: render.DexNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}},
					&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraOperatorSecrets, Namespace: render.DexNamespace}},
					&csisecret.SecretProviderClass{ObjectMeta: metav1.ObjectMeta{Name: render.OIDCSecretName, Namespace: render.DexNamespace}, TypeMeta: metav1.TypeMeta{Kind: "SecretProviderClass", APIVersion: "secrets-store.csi.x-k8s.io/v1"}},
				}

				rtest.ExpectResources(resources, expectedResources)

				Expect(rtest.GetResource(resources, render.OIDCSecretName, common.OperatorNamespace(), "", "v1", "Secret")).To(BeNil())
				Expect(rtest.GetResource(resources, render.OIDCSecretName, render.DexNamespace, "", "v1", "Secret")).To(BeNil())

				d := rtest.GetResource(resources, render.DexObjectName, render.DexNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
				Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
				Expect(d.Spec.Template.Spec.Containers[0].Env).To(ContainElement(corev1.EnvVar{Name: "WATCH_DIR", Value: "/mnt/secrets-store"}))

				Expect(d.Spec.Template.Spec.Containers[0].VolumeMounts).To(ContainElement(corev1.VolumeMount{Name: "secrets-store", MountPath: "/mnt/secrets-store", ReadOnly: true}))
				var secretsStoreVol *corev1.Volume
				for i := range d.Spec.Template.Spec.Volumes {
					if d.Spec.Template.Spec.Volumes[i].Name == "secrets-store" {
						secretsStoreVol = &d.Spec.Template.Spec.Volumes[i]
						break
					}
				}
				Expect(secretsStoreVol).NotTo(BeNil())
				Expect(secretsStoreVol.CSI).NotTo(BeNil())
				Expect(secretsStoreVol.CSI.Driver).To(Equal("secrets-store.csi.k8s.io"))
				Expect(secretsStoreVol.CSI.VolumeAttributes).To(HaveKeyWithValue("secretProviderClass", render.OIDCSecretName))
			})
		})

		It("should switch from Kubernetes Secret to SecretProviderClass", func() {
			cfg.Authentication = authentication

			// Initial render with Kubernetes Secret.
			component := render.Dex(cfg)
			resources, _ := component.Objects()

			Expect(rtest.GetResource(resources, render.OIDCSecretName, render.DexNamespace, "", "v1", "Secret")).NotTo(BeNil())
			Expect(rtest.GetResource(resources, render.OIDCSecretName, render.DexNamespace, "secrets-store.csi.x-k8s.io", "v1", "SecretProviderClass")).To(BeNil())

			d := rtest.GetResource(resources, render.DexObjectName, render.DexNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(d.Spec.Template.Annotations).To(HaveKey("hash.operator.tigera.io/tigera-idp-secret"))

			// Update configuration to use SecretProviderClass.
			spc := &csisecret.SecretProviderClass{
				TypeMeta:   metav1.TypeMeta{Kind: "SecretProviderClass", APIVersion: "secrets-store.csi.x-k8s.io/v1"},
				ObjectMeta: metav1.ObjectMeta{Name: render.OIDCSecretName, Namespace: common.OperatorNamespace()},
			}
			cfg.DexConfig = render.NewDexConfig(cfg.Installation.CertificateManagement, authentication, nil, spc, clusterName)

			component = render.Dex(cfg)
			resources, _ = component.Objects()

			Expect(rtest.GetResource(resources, render.OIDCSecretName, render.DexNamespace, "", "v1", "Secret")).To(BeNil())
			Expect(rtest.GetResource(resources, render.OIDCSecretName, render.DexNamespace, "secrets-store.csi.x-k8s.io", "v1", "SecretProviderClass")).NotTo(BeNil())

			d = rtest.GetResource(resources, render.DexObjectName, render.DexNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(d.Spec.Template.Annotations).NotTo(HaveKey("hash.operator.tigera.io/tigera-idp-secret"))
			Expect(d.Spec.Template.Spec.Containers[0].Env).To(ContainElement(corev1.EnvVar{Name: "WATCH_DIR", Value: "/mnt/secrets-store"}))
		})

		It("should apply tolerations", func() {
			t := corev1.Toleration{
				Key:      "foo",
				Operator: corev1.TolerationOpEqual,
				Value:    "bar",
				Effect:   corev1.TaintEffectNoExecute,
			}
			cfg.Installation.ControlPlaneTolerations = []corev1.Toleration{t}

			component := render.Dex(cfg)
			resources, _ := component.Objects()
			d := rtest.GetResource(resources, render.DexObjectName, render.DexNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(d.Spec.Template.Spec.Tolerations).To(ContainElements(append(rmeta.TolerateControlPlane, t)))
		})

		It("should render toleration on GKE", func() {
			cfg.Installation.KubernetesProvider = operatorv1.ProviderGKE

			component := render.Dex(cfg)
			resources, _ := component.Objects()
			d := rtest.GetResource(resources, render.DexObjectName, render.DexNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(d).NotTo(BeNil())
			Expect(d.Spec.Template.Spec.Tolerations).To(ContainElements(corev1.Toleration{
				Key:      "kubernetes.io/arch",
				Operator: corev1.TolerationOpEqual,
				Value:    "arm64",
				Effect:   corev1.TaintEffectNoSchedule,
			}))
		})

		It("should render all resources for a certificate management", func() {
			cfg.Installation.CertificateManagement = &operatorv1.CertificateManagement{}
			cfg.DexConfig = render.NewDexConfig(cfg.Installation.CertificateManagement, authentication, idpSecret, nil, clusterName)

			component := render.Dex(cfg)
			resources, _ := component.Objects()

			expectedResources := []client.Object{
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: render.DexObjectName}, TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"}},
				&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: render.DexPolicyName, Namespace: render.DexNamespace}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
				&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: networkpolicy.CalicoComponentDefaultDenyPolicyName, Namespace: render.DexNamespace}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
				&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: render.DexObjectName, Namespace: render.DexNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
				&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: render.DexObjectName, Namespace: render.DexNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"}},
				&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: render.DexObjectName, Namespace: render.DexNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},
				&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: render.DexObjectName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
				&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.DexObjectName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
				&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: render.DexObjectName, Namespace: render.DexNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.OIDCSecretName, Namespace: common.OperatorNamespace()}, TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: render.OIDCSecretName, Namespace: render.DexNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}},
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: pullSecretName, Namespace: render.DexNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}},
				&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "tigera-dex:csr-creator"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
				&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.TigeraOperatorSecrets, Namespace: render.DexNamespace}},
			}

			rtest.ExpectResources(resources, expectedResources)
		})

		It("should render SecurityContextConstrains properly when provider is OpenShift", func() {
			cfg.Installation.KubernetesProvider = operatorv1.ProviderOpenShift
			cfg.OpenShift = true
			component := render.Dex(cfg)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()

			role := rtest.GetResource(resources, "tigera-dex", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
			Expect(role.Rules).To(ContainElement(rbacv1.PolicyRule{
				APIGroups:     []string{"security.openshift.io"},
				Resources:     []string{"securitycontextconstraints"},
				Verbs:         []string{"use"},
				ResourceNames: []string{"nonroot-v2"},
			}))
		})

		It("should not render PodAffinity when ControlPlaneReplicas is 1", func() {
			var replicas int32 = 1
			cfg.Installation.ControlPlaneReplicas = &replicas

			component := render.Dex(cfg)
			resources, _ := component.Objects()
			deploy, ok := rtest.GetResource(resources, render.DexObjectName, render.DexNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue())
			Expect(deploy.Spec.Template.Spec.Affinity).To(BeNil())
		})

		It("should render PodAffinity when ControlPlaneReplicas is greater than 1", func() {
			var replicas int32 = 2
			cfg.Installation.ControlPlaneReplicas = &replicas

			component := render.Dex(cfg)
			resources, _ := component.Objects()
			deploy, ok := rtest.GetResource(resources, render.DexObjectName, render.DexNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue())
			Expect(deploy.Spec.Template.Spec.Affinity).NotTo(BeNil())
			Expect(deploy.Spec.Template.Spec.Affinity).To(Equal(podaffinity.NewPodAntiAffinity("tigera-dex", []string{"tigera-dex"})))
		})

		It("should render configuration with resource requests and limits", func() {
			ca, _ := tls.MakeCA(rmeta.DefaultOperatorCASignerName())
			cert, _, _ := ca.Config.GetPEMBytes() // create a valid pem block
			cfg.Installation.CertificateManagement = &operatorv1.CertificateManagement{CACert: cert}

			certificateManager, err := certificatemanager.Create(cli, cfg.Installation, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
			Expect(err).NotTo(HaveOccurred())

			dnsNames := dns.GetServiceDNSNames(render.DexObjectName, render.DexNamespace, clusterDomain)
			dexTLS, err := certificateManager.GetOrCreateKeyPair(cli, render.DexTLSSecretName, common.OperatorNamespace(), dnsNames)
			Expect(err).NotTo(HaveOccurred())
			cfg.TLSKeyPair = dexTLS

			dexResources := corev1.ResourceRequirements{
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

			dexInitContainerResources := corev1.ResourceRequirements{
				Limits: corev1.ResourceList{
					"cpu":    resource.MustParse("100m"),
					"memory": resource.MustParse("100Mi"),
				},
				Requests: corev1.ResourceList{
					"cpu":    resource.MustParse("10m"),
					"memory": resource.MustParse("150Mi"),
				},
			}

			cfg.Authentication = &operatorv1.Authentication{
				Spec: operatorv1.AuthenticationSpec{
					DexDeployment: &operatorv1.DexDeployment{
						Spec: &operatorv1.DexDeploymentSpec{
							Template: &operatorv1.DexDeploymentPodTemplateSpec{
								Spec: &operatorv1.DexDeploymentPodSpec{
									Containers: []operatorv1.DexDeploymentContainer{{
										Name:      "tigera-dex",
										Resources: &dexResources,
									}},
									InitContainers: []operatorv1.DexDeploymentInitContainer{{
										Name:      "tigera-dex-tls-key-cert-provisioner",
										Resources: &dexInitContainerResources,
									}},
								},
							},
						},
					},
				},
			}

			component := render.Dex(cfg)
			resources, _ := component.Objects()
			deploy, ok := rtest.GetResource(resources, render.DexObjectName, render.DexNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue())
			Expect(deploy.Spec.Template.Spec.Containers).To(HaveLen(1))

			// Should set requests/limits for tigera-dex container
			container := test.GetContainer(deploy.Spec.Template.Spec.Containers, "tigera-dex")
			Expect(container).NotTo(BeNil())
			Expect(container.Resources).To(Equal(dexResources))

			initContainer := test.GetContainer(deploy.Spec.Template.Spec.InitContainers, "tigera-dex-tls-key-cert-provisioner")
			Expect(initContainer).NotTo(BeNil())
			Expect(initContainer.Resources).To(Equal(dexInitContainerResources))
		})
		It("should render configuration with default Init container resource requests and limits", func() {
			ca, _ := tls.MakeCA(rmeta.DefaultOperatorCASignerName())
			cert, _, _ := ca.Config.GetPEMBytes() // create a valid pem block
			cfg.Installation.CertificateManagement = &operatorv1.CertificateManagement{CACert: cert}

			certificateManager, err := certificatemanager.Create(cli, cfg.Installation, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
			Expect(err).NotTo(HaveOccurred())

			dnsNames := dns.GetServiceDNSNames(render.DexObjectName, render.DexNamespace, clusterDomain)
			dexTLS, err := certificateManager.GetOrCreateKeyPair(cli, render.DexTLSSecretName, common.OperatorNamespace(), dnsNames)
			Expect(err).NotTo(HaveOccurred())
			cfg.TLSKeyPair = dexTLS

			component := render.Dex(cfg)
			resources, _ := component.Objects()
			deploy, ok := rtest.GetResource(resources, render.DexObjectName, render.DexNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue())
			Expect(deploy.Spec.Template.Spec.Containers).To(HaveLen(1))

			initContainer := test.GetContainer(deploy.Spec.Template.Spec.InitContainers, "tigera-dex-tls-key-cert-provisioner")
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

		Context("calico-system rendering", func() {
			policyName := types.NamespacedName{Name: "calico-system.dex", Namespace: "tigera-dex"}

			getExpectedPolicy := func(scenario testutils.CalicoSystemScenario) *v3.NetworkPolicy {
				if scenario.ManagedCluster {
					return nil
				}

				return testutils.SelectPolicyByProvider(scenario, expectedDexPolicy, expectedDexOpenshiftPolicy)
			}

			DescribeTable("should render calico-system policy",
				func(scenario testutils.CalicoSystemScenario) {
					cfg.OpenShift = scenario.OpenShift
					component := render.Dex(cfg)
					resources, _ := component.Objects()

					policy := testutils.GetCalicoSystemPolicyFromResources(policyName, resources)
					expectedPolicy := getExpectedPolicy(scenario)
					Expect(policy.Spec.Selector).To(Equal(policy.Spec.Selector))
					Expect(policy.Spec.Tier).To(Equal(policy.Spec.Tier))
					Expect(policy.Spec.Order).To(Equal(policy.Spec.Order))
					Expect(policy.Spec.Types).To(Equal(policy.Spec.Types))

					// The order of insertion of rules is not guaranteed by the render implementation.
					Expect(policy.Spec.Ingress).To(ContainElements(expectedPolicy.Spec.Ingress))
					Expect(policy.Spec.Egress).To(ContainElements(expectedPolicy.Spec.Egress))
				},
				// Dex only renders in the presence of an Authentication CR, therefore does not have a config option for managed clusters.
				Entry("for management/standalone, kube-dns", testutils.CalicoSystemScenario{ManagedCluster: false, OpenShift: false}),
				Entry("for management/standalone, openshift-dns", testutils.CalicoSystemScenario{ManagedCluster: false, OpenShift: true}),
			)
		})
	})
})

// ConfigYAML is a slimmed down version of https://github.com/dexidp/dex/blob/v2.45.1/cmd/dex/config.go
type ConfigYAML struct {
	Web           Web             `yaml:"web"`
	StaticClients []StaticClients `yaml:"staticClients"`
	Expiry        Expiry          `yaml:"expiry"`
}

type Web struct {
	Headers Headers `json:"headers"`
}

type StaticClients struct {
	RedirectURIs []string `yaml:"redirectURIs"`
}

type Expiry struct {
	IDTokens string `yaml:"idTokens"`
}

type Headers struct {
	ContentSecurityPolicy   string `yaml:"Content-Security-Policy"`
	XFrameOptions           string `yaml:"X-Frame-Options"`
	XContentTypeOptions     string `yaml:"X-Content-Type-Options"`
	XXSSProtection          string `yaml:"X-XSS-Protection"`
	StrictTransportSecurity string `yaml:"Strict-Transport-Security"`
}
