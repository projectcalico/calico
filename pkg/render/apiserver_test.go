// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.

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
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gstruct"

	"github.com/openshift/library-go/pkg/crypto"

	calicov3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/podaffinity"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/testutils"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"github.com/tigera/operator/test"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	apiregv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("API server rendering tests (Calico Enterprise)", func() {
	apiServerPolicy := testutils.GetExpectedPolicyFromFile("./testutils/expected_policies/apiserver.json")
	apiServerPolicyForOCP := testutils.GetExpectedPolicyFromFile("./testutils/expected_policies/apiserver_ocp.json")
	var (
		instance           *operatorv1.InstallationSpec
		apiserver          *operatorv1.APIServerSpec
		managementCluster  = &operatorv1.ManagementCluster{Spec: operatorv1.ManagementClusterSpec{Address: "example.com:1234"}}
		cfg                *render.APIServerConfiguration
		trustedBundle      certificatemanagement.TrustedBundle
		dnsNames           []string
		cli                client.Client
		certificateManager certificatemanager.CertificateManager
		err                error
	)

	BeforeEach(func() {
		instance = &operatorv1.InstallationSpec{
			ControlPlaneReplicas: ptr.To[int32](2),
			Registry:             "testregistry.com/",
			Variant:              operatorv1.TigeraSecureEnterprise,
		}
		apiserver = &operatorv1.APIServerSpec{}
		dnsNames = dns.GetServiceDNSNames(render.APIServerServiceName, render.APIServerNamespace, clusterDomain)
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())

		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
		certificateManager, err = certificatemanager.Create(cli, nil, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())

		kp, err := certificateManager.GetOrCreateKeyPair(cli, render.CalicoAPIServerTLSSecretName, common.OperatorNamespace(), dnsNames)
		Expect(err).NotTo(HaveOccurred())

		trustedBundle = certificatemanagement.CreateTrustedBundle(nil)

		cfg = &render.APIServerConfiguration{
			RequiresAggregationServer: true,
			K8SServiceEndpoint:        k8sapi.ServiceEndpoint{},
			Installation:              instance,
			APIServer:                 apiserver,
			OpenShift:                 true,
			TLSKeyPair:                kp,
			TrustedBundle:             trustedBundle,
			KubernetesVersion: &common.VersionInfo{
				Major: 1,
				Minor: 31,
			},
		}
	})

	DescribeTable("should render an API server with default configuration", func(clusterDomain string) {
		expectedResources := []client.Object{
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "calico-audit-policy", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}},
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "tigera-ca-bundle", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-crds"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-access-calico-crds"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-tier-getter"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-tier-getter"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-tiered-policy-passthrough"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-tiered-policy-passthrough"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-uisettings-passthrough"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-uisettings-passthrough"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-extension-apiserver-auth-access"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-extension-apiserver-auth-access"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-delegate-auth"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-auth-reader", Namespace: "kube-system"}, TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&apiregv1.APIService{ObjectMeta: metav1.ObjectMeta{Name: "v3.projectcalico.org"}, TypeMeta: metav1.TypeMeta{Kind: "APIService", APIVersion: "apiregistration.k8s.io/v1"}},
			&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "calico-api", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},
			&policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "PodDisruptionBudget", APIVersion: "policy/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-uisettingsgroup-getter"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-uisettingsgroup-getter"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-ui-user"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-network-admin"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-webhook-reader"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-webhook-reader"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
		}

		dnsNames := dns.GetServiceDNSNames(render.APIServerServiceName, render.APIServerNamespace, clusterDomain)
		kp, err := certificateManager.GetOrCreateKeyPair(cli, render.CalicoAPIServerTLSSecretName, common.OperatorNamespace(), dnsNames)
		Expect(err).NotTo(HaveOccurred())
		cfg.TLSKeyPair = kp
		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())

		resources, _ := component.Objects()

		// Should render the correct resources.
		// - 1 namespace
		// - 1 ConfigMap audit Policy
		// - 1 ConfigMap Tigera CA bundle
		// - 1 Service account
		// - 2 ServiceAccount ClusterRole and binding for calico CRDs
		// - 2 ServiceAccount ClusterRole and binding for tigera CRDs
		// - 2 ClusterRole and binding for auth configmap
		// - 2 calico policy passthru ClusterRole and binding
		// - 2 tiered policy passthru ClusterRole and binding
		// - 1 Role binding for tigera-operator to manage secrets
		// - 1 delegate auth binding
		// - 1 auth reader binding
		// - 2 webhook reader ClusterRole and binding
		// - 2 cert secrets
		// - 1 api server
		// - 1 service registration
		// - 1 Server service
		rtest.ExpectResources(resources, expectedResources)

		apiService, ok := rtest.GetResource(resources, "v3.projectcalico.org", "", "apiregistration.k8s.io", "v1", "APIService").(*apiregv1.APIService)
		Expect(ok).To(BeTrue(), "Expected v1.APIService")
		verifyAPIService(apiService, true, clusterDomain)

		d := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment").(*appsv1.Deployment)

		Expect(d.Name).To(Equal("calico-apiserver"))
		Expect(len(d.Labels)).To(Equal(1))
		Expect(d.Labels).To(HaveKeyWithValue("apiserver", "true"))

		Expect(*d.Spec.Replicas).To(BeEquivalentTo(2))
		Expect(d.Spec.Strategy.Type).To(Equal(appsv1.RollingUpdateDeploymentStrategyType))
		Expect(len(d.Spec.Selector.MatchLabels)).To(Equal(1))
		Expect(d.Spec.Selector.MatchLabels).To(HaveKeyWithValue("apiserver", "true"))

		Expect(d.Spec.Template.Name).To(Equal("calico-apiserver"))
		Expect(d.Spec.Template.Namespace).To(Equal("calico-system"))
		Expect(len(d.Spec.Template.Labels)).To(Equal(1))
		Expect(d.Spec.Template.Labels).To(HaveKeyWithValue("apiserver", "true"))

		Expect(d.Spec.Template.Spec.ServiceAccountName).To(Equal("calico-apiserver"))

		Expect(d.Spec.Template.Spec.Tolerations).To(ConsistOf(rmeta.TolerateControlPlane))

		Expect(d.Spec.Template.Spec.ImagePullSecrets).To(BeEmpty())
		Expect(d.Spec.Template.Spec.Containers).To(HaveLen(2))
		Expect(d.Spec.Template.Spec.Containers[0].Name).To(Equal("calico-apiserver"))
		Expect(d.Spec.Template.Spec.Containers[0].Image).To(Equal(
			fmt.Sprintf("testregistry.com/%s%s:%s", components.TigeraImagePath, components.ComponentAPIServer.Image, components.ComponentAPIServer.Version),
		))

		expectedArgs := []string{
			"--secure-port=5443",
			"--tls-private-key-file=/calico-apiserver-certs/tls.key",
			"--tls-cert-file=/calico-apiserver-certs/tls.crt",
			"--audit-policy-file=/etc/tigera/audit/policy.conf",
			"--audit-log-path=/var/log/calico/audit/tsee-audit.log",
		}
		Expect(d.Spec.Template.Spec.Containers[0].Args).To(ConsistOf(expectedArgs))
		Expect(len(d.Spec.Template.Spec.Containers[0].Env)).To(Equal(2))
		Expect(d.Spec.Template.Spec.Containers[0].Env[0].Name).To(Equal("DATASTORE_TYPE"))
		Expect(d.Spec.Template.Spec.Containers[0].Env[0].Value).To(Equal("kubernetes"))
		Expect(d.Spec.Template.Spec.Containers[0].Env[0].ValueFrom).To(BeNil())
		Expect(d.Spec.Template.Spec.Containers[0].Env[1].Name).To(Equal("LOG_LEVEL"))
		Expect(d.Spec.Template.Spec.Containers[0].Env[1].Value).To(Equal("info"))
		Expect(d.Spec.Template.Spec.Containers[0].Env[1].ValueFrom).To(BeNil())

		Expect(len(d.Spec.Template.Spec.Containers[0].VolumeMounts)).To(Equal(3))
		Expect(d.Spec.Template.Spec.Containers[0].VolumeMounts[0].Name).To(Equal("calico-apiserver-certs"))
		Expect(d.Spec.Template.Spec.Containers[0].VolumeMounts[1].MountPath).To(Equal("/var/log/calico/audit"))
		Expect(d.Spec.Template.Spec.Containers[0].VolumeMounts[1].Name).To(Equal("calico-audit-logs"))

		Expect(d.Spec.Template.Spec.Containers[0].ReadinessProbe.HTTPGet.Path).To(Equal("/readyz"))
		Expect(d.Spec.Template.Spec.Containers[0].ReadinessProbe.HTTPGet.Port.String()).To(BeEquivalentTo("5443"))
		Expect(d.Spec.Template.Spec.Containers[0].ReadinessProbe.HTTPGet.Scheme).To(BeEquivalentTo("HTTPS"))
		Expect(d.Spec.Template.Spec.Containers[0].ReadinessProbe.PeriodSeconds).To(BeEquivalentTo(60))

		Expect(*d.Spec.Template.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation).To(BeTrue())
		Expect(*d.Spec.Template.Spec.Containers[0].SecurityContext.Privileged).To(BeTrue())
		Expect(*d.Spec.Template.Spec.Containers[0].SecurityContext.RunAsGroup).To(BeEquivalentTo(0))
		Expect(*d.Spec.Template.Spec.Containers[0].SecurityContext.RunAsNonRoot).To(BeFalse())
		Expect(*d.Spec.Template.Spec.Containers[0].SecurityContext.RunAsUser).To(BeEquivalentTo(0))
		Expect(d.Spec.Template.Spec.Containers[0].SecurityContext.Capabilities).To(Equal(
			&corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		))
		Expect(d.Spec.Template.Spec.Containers[0].SecurityContext.SeccompProfile).To(Equal(
			&corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			}))

		Expect(d.Spec.Template.Spec.Containers[1].Name).To(Equal("tigera-queryserver"))
		Expect(d.Spec.Template.Spec.Containers[1].Image).To(Equal(
			fmt.Sprintf("testregistry.com/%s%s:%s", components.TigeraImagePath, components.ComponentQueryServer.Image, components.ComponentQueryServer.Version),
		))
		Expect(d.Spec.Template.Spec.Containers[1].Args).To(BeEmpty())

		Expect(d.Spec.Template.Spec.Containers[1].Env).To(HaveLen(10))

		Expect(d.Spec.Template.Spec.Containers[1].Env[0].Name).To(Equal("DATASTORE_TYPE"))
		Expect(d.Spec.Template.Spec.Containers[1].Env[0].Value).To(Equal("kubernetes"))
		Expect(d.Spec.Template.Spec.Containers[1].Env[0].ValueFrom).To(BeNil())
		Expect(d.Spec.Template.Spec.Containers[1].Env[1].Name).To(Equal("LISTEN_ADDR"))
		Expect(d.Spec.Template.Spec.Containers[1].Env[1].Value).To(Equal(":8080"))
		Expect(d.Spec.Template.Spec.Containers[1].Env[1].ValueFrom).To(BeNil())
		Expect(d.Spec.Template.Spec.Containers[1].Env[2].Name).To(Equal("TLS_CERT"))
		Expect(d.Spec.Template.Spec.Containers[1].Env[2].Value).To(Equal("/calico-apiserver-certs/tls.crt"))
		Expect(d.Spec.Template.Spec.Containers[1].Env[2].ValueFrom).To(BeNil())
		Expect(d.Spec.Template.Spec.Containers[1].Env[3].Name).To(Equal("TLS_KEY"))
		Expect(d.Spec.Template.Spec.Containers[1].Env[3].Value).To(Equal("/calico-apiserver-certs/tls.key"))
		Expect(d.Spec.Template.Spec.Containers[1].Env[3].ValueFrom).To(BeNil())
		Expect(d.Spec.Template.Spec.Containers[1].Env[4].Name).To(Equal("TRUSTED_BUNDLE_PATH"))
		Expect(d.Spec.Template.Spec.Containers[1].Env[4].Value).To(Equal("/etc/pki/tls/certs/tigera-ca-bundle.crt"))
		Expect(d.Spec.Template.Spec.Containers[1].Env[5].Name).To(Equal("LINSEED_URL"))
		Expect(d.Spec.Template.Spec.Containers[1].Env[5].Value).To(Equal("https://tigera-linseed.tigera-elasticsearch.svc"))
		Expect(d.Spec.Template.Spec.Containers[1].Env[6].Name).To(Equal("LINSEED_CLIENT_CERT"))
		Expect(d.Spec.Template.Spec.Containers[1].Env[6].Value).To(Equal("/calico-apiserver-certs/tls.crt"))
		Expect(d.Spec.Template.Spec.Containers[1].Env[7].Name).To(Equal("LINSEED_CLIENT_KEY"))
		Expect(d.Spec.Template.Spec.Containers[1].Env[7].Value).To(Equal("/calico-apiserver-certs/tls.key"))
		Expect(d.Spec.Template.Spec.Containers[1].Env[8].Name).To(Equal("LINSEED_CA"))
		Expect(d.Spec.Template.Spec.Containers[1].Env[8].Value).To(Equal("/etc/pki/tls/certs/tigera-ca-bundle.crt"))
		Expect(d.Spec.Template.Spec.Containers[1].Env[9].Name).To(Equal("LOGLEVEL"))
		Expect(d.Spec.Template.Spec.Containers[1].Env[9].Value).To(Equal("info"))
		Expect(d.Spec.Template.Spec.Containers[1].Env[9].ValueFrom).To(BeNil())

		// Expect the SECURITY_GROUP env variables to not be set
		Expect(d.Spec.Template.Spec.Containers[1].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_DEFAULT_SECURITY_GROUPS")})))
		Expect(d.Spec.Template.Spec.Containers[1].Env).NotTo(ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{"Name": Equal("TIGERA_POD_SECURITY_GROUP")})))

		Expect(d.Spec.Template.Spec.Containers[1].VolumeMounts).To(HaveLen(2))
		Expect(d.Spec.Template.Spec.Containers[1].VolumeMounts[0].Name).To(Equal("calico-apiserver-certs"))
		Expect(d.Spec.Template.Spec.Containers[1].VolumeMounts[0].MountPath).To(Equal("/calico-apiserver-certs"))
		Expect(d.Spec.Template.Spec.Containers[1].VolumeMounts[0].ReadOnly).To(BeTrue())
		Expect(d.Spec.Template.Spec.Containers[1].VolumeMounts[0].SubPath).To(Equal(""))
		Expect(d.Spec.Template.Spec.Containers[1].VolumeMounts[0].MountPropagation).To(BeNil())
		Expect(d.Spec.Template.Spec.Containers[1].VolumeMounts[0].SubPathExpr).To(Equal(""))
		Expect(d.Spec.Template.Spec.Containers[1].VolumeMounts[1].Name).To(Equal("tigera-ca-bundle"))
		Expect(d.Spec.Template.Spec.Containers[1].VolumeMounts[1].MountPath).To(Equal("/etc/pki/tls/certs"))
		Expect(d.Spec.Template.Spec.Containers[1].VolumeMounts[1].ReadOnly).To(BeTrue())
		Expect(d.Spec.Template.Spec.Containers[1].VolumeMounts[1].SubPath).To(Equal(""))
		Expect(d.Spec.Template.Spec.Containers[1].VolumeMounts[1].MountPropagation).To(BeNil())
		Expect(d.Spec.Template.Spec.Containers[1].VolumeMounts[1].SubPathExpr).To(Equal(""))

		Expect(d.Spec.Template.Spec.Containers[1].LivenessProbe.HTTPGet.Path).To(Equal("/version"))
		Expect(d.Spec.Template.Spec.Containers[1].LivenessProbe.HTTPGet.Port.String()).To(BeEquivalentTo("8080"))
		Expect(d.Spec.Template.Spec.Containers[1].LivenessProbe.HTTPGet.Scheme).To(BeEquivalentTo("HTTPS"))
		Expect(d.Spec.Template.Spec.Containers[1].LivenessProbe.InitialDelaySeconds).To(BeEquivalentTo(90))

		Expect(*d.Spec.Template.Spec.Containers[1].SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
		Expect(*d.Spec.Template.Spec.Containers[1].SecurityContext.Privileged).To(BeFalse())
		Expect(*d.Spec.Template.Spec.Containers[1].SecurityContext.RunAsGroup).To(BeEquivalentTo(10001))
		Expect(*d.Spec.Template.Spec.Containers[1].SecurityContext.RunAsNonRoot).To(BeTrue())
		Expect(*d.Spec.Template.Spec.Containers[1].SecurityContext.RunAsUser).To(BeEquivalentTo(10001))
		Expect(d.Spec.Template.Spec.Containers[1].SecurityContext.Capabilities).To(Equal(
			&corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		))
		Expect(d.Spec.Template.Spec.Containers[1].SecurityContext.SeccompProfile).To(Equal(
			&corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			}))

		Expect(d.Spec.Template.Spec.Volumes).To(HaveLen(4))
		Expect(d.Spec.Template.Spec.Volumes[0].Name).To(Equal("calico-apiserver-certs"))
		Expect(d.Spec.Template.Spec.Volumes[0].Secret.SecretName).To(Equal("calico-apiserver-certs"))
		Expect(d.Spec.Template.Spec.Volumes[1].Name).To(Equal("calico-audit-logs"))
		Expect(d.Spec.Template.Spec.Volumes[1].HostPath.Path).To(Equal("/var/log/calico/audit"))
		Expect(*d.Spec.Template.Spec.Volumes[1].HostPath.Type).To(BeEquivalentTo("DirectoryOrCreate"))
		Expect(d.Spec.Template.Spec.Volumes[2].Name).To(Equal("calico-audit-policy"))
		Expect(d.Spec.Template.Spec.Volumes[2].ConfigMap.Name).To(Equal("calico-audit-policy"))
		Expect(d.Spec.Template.Spec.Volumes[2].ConfigMap.Items).To(HaveLen(1))
		Expect(d.Spec.Template.Spec.Volumes[2].ConfigMap.Items[0].Key).To(Equal("config"))
		Expect(d.Spec.Template.Spec.Volumes[2].ConfigMap.Items[0].Path).To(Equal("policy.conf"))
		Expect(d.Spec.Template.Spec.Volumes[3].Name).To(Equal("tigera-ca-bundle"))
		Expect(d.Spec.Template.Spec.Volumes[3].ConfigMap.Name).To(Equal("tigera-ca-bundle"))

		clusterRole := rtest.GetResource(resources, "tigera-network-admin", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(clusterRole.Rules).To(ConsistOf(networkAdminPolicyRules))

		clusterRole = rtest.GetResource(resources, "tigera-ui-user", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(clusterRole.Rules).To(ConsistOf(uiUserPolicyRules))

		clusterRoleBinding := rtest.GetResource(resources, "calico-extension-apiserver-auth-access", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
		Expect(clusterRoleBinding.RoleRef.Name).To(Equal("calico-extension-apiserver-auth-access"))

		svc := rtest.GetResource(resources, "calico-api", "calico-system", "", "v1", "Service").(*corev1.Service)
		Expect(svc.GetObjectMeta().GetLabels()).To(HaveLen(1))
		Expect(svc.GetObjectMeta().GetLabels()).To(HaveKeyWithValue("k8s-app", "calico-api"))

		Expect(svc.Spec.Ports).To(HaveLen(2))
		serviceFound := 0
		for _, p := range svc.Spec.Ports {
			switch p.Name {
			case render.APIServerPortName:
				Expect(p.Port).To(Equal(int32(443)))
				Expect(p.TargetPort.IntValue()).To(Equal(5443))
				serviceFound++
			case render.QueryServerPortName:
				Expect(p.Port).To(Equal(int32(8080)))
				Expect(p.TargetPort.IntValue()).To(Equal(8080))
				serviceFound++
			}
		}
		Expect(serviceFound).To(Equal(2))

		cr := rtest.GetResource(resources, "calico-tiered-policy-passthrough", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		var tieredPolicyRules []string
		for _, rule := range cr.Rules {
			tieredPolicyRules = append(tieredPolicyRules, rule.Resources...)
		}
		Expect(tieredPolicyRules).To(ContainElements("networkpolicies", "globalnetworkpolicies", "stagednetworkpolicies", "stagedglobalnetworkpolicies"))

		apiserverClusterRole := rtest.GetResource(resources,
			"calico-crds", "", rbacv1.GroupName, "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(apiserverClusterRole.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups: []string{"admissionregistration.k8s.io"},
			Resources: []string{
				"validatingadmissionpolicies",
				"validatingadmissionpolicybindings",
			},
			Verbs: []string{
				"get",
				"list",
				"watch",
			},
		}))
	},
		Entry("default cluster domain", dns.DefaultClusterDomain),
		Entry("custom cluster domain", "custom-domain.internal"),
	)

	It("should render resources without an aggregation server", func() {
		cfg.RequiresAggregationServer = false

		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		resources, _ := component.Objects()

		expectedResources := []client.Object{
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "tigera-ca-bundle", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-crds"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-access-calico-crds"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-tier-getter"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-tier-getter"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-delegate-auth"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "calico-api", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},
			&policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "PodDisruptionBudget", APIVersion: "policy/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-ui-user"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-network-admin"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-webhook-reader"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-webhook-reader"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
		}

		rtest.ExpectResources(resources, expectedResources)

		// In CRD/webhooks mode the calico-uisettings-passthrough ClusterRole is not deployed, so
		// tigera-network-admin needs to grant write access to uisettings itself for the
		// calico-webhooks UISettings handler to do the narrowing instead of being short-circuited
		// by kube-apiserver RBAC.
		networkAdmin := rtest.GetResource(resources, "tigera-network-admin", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(networkAdmin.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"uisettings"},
			Verbs:     []string{"create", "update", "delete", "patch"},
		}))
	})

	It("binds the previous API server to the CRD role while the cutover is held", func() {
		// v1.38 created calico-apiserver-access-calico-crds with the previous service account, so
		// narrowing it to one subject mid-migration stops the API server that is still serving.
		subjectsFor := func(hold bool) []rbacv1.Subject {
			cfg.HoldAPIServiceCutover = hold
			component, err := render.APIServer(cfg)
			Expect(err).To(BeNil())
			resources, _ := component.Objects()
			crb := rtest.GetResource(resources, "calico-apiserver-access-calico-crds", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding")
			Expect(crb).NotTo(BeNil())
			return crb.(*rbacv1.ClusterRoleBinding).Subjects
		}

		held := subjectsFor(true)
		Expect(held).To(ContainElement(rbacv1.Subject{Kind: "ServiceAccount", Name: "calico-apiserver", Namespace: "calico-system"}))
		Expect(held).To(ContainElement(rbacv1.Subject{Kind: "ServiceAccount", Name: "tigera-apiserver", Namespace: "tigera-system"}))

		done := subjectsFor(false)
		Expect(done).To(HaveLen(1))
		Expect(done).To(ContainElement(rbacv1.Subject{Kind: "ServiceAccount", Name: "calico-apiserver", Namespace: "calico-system"}))
	})

	It("should grant the calico-apiserver SA write access to globalreports/status", func() {
		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		resources, _ := component.Objects()

		cr := rtest.GetResource(resources, "calico-apiserver", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)

		// Find the backing-storage rule and assert it covers globalreports/status.
		// Without this, compliance-controller can't update status.lastScheduledReportJob
		// and no compliance jobs ever run.
		var found bool
		for _, rule := range cr.Rules {
			hasGlobalReports := false
			hasGlobalReportsStatus := false
			for _, r := range rule.Resources {
				if r == "globalreports" {
					hasGlobalReports = true
				}
				if r == "globalreports/status" {
					hasGlobalReportsStatus = true
				}
			}
			if hasGlobalReports {
				found = true
				Expect(hasGlobalReportsStatus).To(BeTrue(), "calico-apiserver ClusterRole rule covering globalreports must also cover globalreports/status")
				Expect(rule.Verbs).To(ContainElement("update"))
			}
		}
		Expect(found).To(BeTrue(), "calico-apiserver ClusterRole should have a rule covering globalreports")
	})

	It("should render L7 Admission Controller with default config when SidecarInjection is Enabled", func() {
		sidecarEnabled := operatorv1.SidecarEnabled
		cfg.ApplicationLayer = &operatorv1.ApplicationLayer{
			Spec: operatorv1.ApplicationLayerSpec{
				SidecarInjection: &sidecarEnabled,
			},
		}

		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		resources, _ := component.Objects()

		d, ok := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(ok).To(BeTrue())
		var container corev1.Container
		for _, c := range d.Spec.Template.Spec.Containers {
			if c.Name == "calico-l7-admission-controller" {
				container = c
			}
		}
		Expect(container.Env[4].Name).To(Equal("L7ADMCTRL_LISTENADDR"))
		Expect(container.Env[4].Value).To(Equal(":6443"))

		// Check the Service configuration
		svc := rtest.GetResource(resources, "calico-api", "calico-system", "", "v1", "Service").(*corev1.Service)
		var servicePort corev1.ServicePort
		for _, p := range svc.Spec.Ports {
			if p.Name == render.L7AdmissionControllerPortName {
				servicePort = p
			}
		}
		Expect(servicePort.Port).To(Equal(int32(6443)))
		Expect(servicePort.TargetPort.IntValue()).To(Equal(6443))
	})

	It("should render log severity when provided", func() {
		errorLog := operatorv1.LogSeverityError
		debugLog := operatorv1.LogSeverityDebug
		cfg.APIServer.Logging = &operatorv1.APIServerPodLogging{
			APIServerLogging: &operatorv1.APIServerLogging{
				LogSeverity: &errorLog,
			},
			QueryServerLogging: &operatorv1.QueryServerLogging{
				LogSeverity: &debugLog,
			},
		}
		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		resources, _ := component.Objects()

		deploy, ok := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(ok).To(BeTrue())

		containers := deploy.Spec.Template.Spec.Containers
		for _, container := range containers {
			envs := container.Env
			if strings.Contains(container.Name, "apiserver") {
				for _, env := range envs {
					if env.Name == "LOG_LEVEL" {
						Expect(env.Value).To(Equal("error"))
					}
				}
			} else if strings.Contains(container.Name, "queryserver") {
				for _, env := range envs {
					if env.Name == "LOGLEVEL" {
						Expect(env.Value).To(Equal("debug"))
					}
				}
			}
		}
		Expect(deploy.Spec.Template.Spec.Containers).NotTo(BeNil())
		Expect(deploy.Spec.Template.Spec.Affinity).To(Equal(podaffinity.NewPodAntiAffinity("calico-apiserver", []string{"calico-system", "tigera-system", "calico-apiserver"})))
	})

	It("should render SecurityContextConstrains properly when provider is OpenShift", func() {
		cfg.Installation.KubernetesProvider = operatorv1.ProviderOpenShift
		cfg.Installation.Variant = operatorv1.TigeraSecureEnterprise
		component, err := render.APIServer(cfg)
		Expect(err).NotTo(HaveOccurred())
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		role := rtest.GetResource(resources, "calico-extension-apiserver-auth-access", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(role.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups:     []string{"security.openshift.io"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
			ResourceNames: []string{"privileged"},
		}))
		Expect(role.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups: []string{"config.openshift.io"},
			Resources: []string{"infrastructures"},
			Verbs:     []string{"get", "list", "watch"},
		}))
	})

	It("should render an API server with custom configuration", func() {
		expectedResources := []client.Object{
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "calico-audit-policy", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}},
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "tigera-ca-bundle", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-crds"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-access-calico-crds"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-tier-getter"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-tier-getter"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-tiered-policy-passthrough"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-tiered-policy-passthrough"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-uisettings-passthrough"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-uisettings-passthrough"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-extension-apiserver-auth-access"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-extension-apiserver-auth-access"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-delegate-auth"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-auth-reader", Namespace: "kube-system"}, TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&apiregv1.APIService{ObjectMeta: metav1.ObjectMeta{Name: "v3.projectcalico.org"}, TypeMeta: metav1.TypeMeta{Kind: "APIService", APIVersion: "apiregistration.k8s.io/v1"}},
			&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "calico-api", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},
			&policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "PodDisruptionBudget", APIVersion: "policy/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-uisettingsgroup-getter"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-uisettingsgroup-getter"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-ui-user"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-network-admin"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-webhook-reader"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-webhook-reader"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
		}

		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		rtest.ExpectResources(resources, expectedResources)

		dep := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment")
		rtest.ExpectResourceTypeAndObjectMetadata(dep, "calico-apiserver", "calico-system", "apps", "v1", "Deployment")
		d := dep.(*appsv1.Deployment)

		Expect(d.Spec.Template.Spec.Volumes).To(HaveLen(4))
	})

	It("should render needed resources for k8s kube-controller", func() {
		expectedResources := []client.Object{
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "calico-audit-policy", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}},
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "tigera-ca-bundle", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-crds"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-access-calico-crds"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-tier-getter"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-tier-getter"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-tiered-policy-passthrough"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-tiered-policy-passthrough"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-uisettings-passthrough"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-uisettings-passthrough"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-extension-apiserver-auth-access"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-extension-apiserver-auth-access"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-delegate-auth"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-auth-reader", Namespace: "kube-system"}, TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&apiregv1.APIService{ObjectMeta: metav1.ObjectMeta{Name: "v3.projectcalico.org"}, TypeMeta: metav1.TypeMeta{Kind: "APIService", APIVersion: "apiregistration.k8s.io/v1"}},
			&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "calico-api", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},
			&policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "PodDisruptionBudget", APIVersion: "policy/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-uisettingsgroup-getter"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-uisettingsgroup-getter"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-ui-user"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-network-admin"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-webhook-reader"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-webhook-reader"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
		}

		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		rtest.ExpectResources(resources, expectedResources)

		// Should render the correct resources.
		cr := rtest.GetResource(resources, "calico-tier-getter", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(len(cr.Rules)).To(Equal(1))
		Expect(len(cr.Rules[0].Resources)).To(Equal(1))
		Expect(cr.Rules[0].Resources[0]).To(Equal("tiers"))
		Expect(len(cr.Rules[0].Verbs)).To(Equal(1))
		Expect(cr.Rules[0].Verbs[0]).To(Equal("get"))

		crb := rtest.GetResource(resources, "calico-tier-getter", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
		Expect(crb.RoleRef.Kind).To(Equal("ClusterRole"))
		Expect(crb.RoleRef.Name).To(Equal("calico-tier-getter"))
		Expect(len(crb.Subjects)).To(Equal(1))
		Expect(crb.Subjects[0].Kind).To(Equal("User"))
		Expect(crb.Subjects[0].Name).To(Equal("system:kube-controller-manager"))

		cr = rtest.GetResource(resources, "calico-uisettingsgroup-getter", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(len(cr.Rules)).To(Equal(1))
		Expect(len(cr.Rules[0].Resources)).To(Equal(1))
		Expect(cr.Rules[0].Resources[0]).To(Equal("uisettingsgroups"))
		Expect(len(cr.Rules[0].Verbs)).To(Equal(1))
		Expect(cr.Rules[0].Verbs[0]).To(Equal("get"))

		crb = rtest.GetResource(resources, "calico-uisettingsgroup-getter", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
		Expect(crb.RoleRef.Kind).To(Equal("ClusterRole"))
		Expect(crb.RoleRef.Name).To(Equal("calico-uisettingsgroup-getter"))
		Expect(len(crb.Subjects)).To(Equal(1))
		Expect(crb.Subjects[0].Kind).To(Equal("User"))
		Expect(crb.Subjects[0].Name).To(Equal("system:kube-controller-manager"))
	})

	It("should include a ControlPlaneNodeSelector when specified", func() {
		expectedResources := []client.Object{
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "calico-audit-policy", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}},
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "tigera-ca-bundle", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-crds"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-access-calico-crds"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-tier-getter"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-tier-getter"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-tiered-policy-passthrough"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-tiered-policy-passthrough"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-uisettings-passthrough"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-uisettings-passthrough"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-extension-apiserver-auth-access"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-extension-apiserver-auth-access"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-delegate-auth"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-auth-reader", Namespace: "kube-system"}, TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&apiregv1.APIService{ObjectMeta: metav1.ObjectMeta{Name: "v3.projectcalico.org"}, TypeMeta: metav1.TypeMeta{Kind: "APIService", APIVersion: "apiregistration.k8s.io/v1"}},
			&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "calico-api", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},
			&policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "PodDisruptionBudget", APIVersion: "policy/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-uisettingsgroup-getter"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-uisettingsgroup-getter"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-ui-user"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-network-admin"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-webhook-reader"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-webhook-reader"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
		}

		cfg.Installation.ControlPlaneNodeSelector = map[string]string{"nodeName": "control01"}
		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		rtest.ExpectResources(resources, expectedResources)

		d := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment").(*appsv1.Deployment)

		Expect(d.Spec.Template.Spec.NodeSelector).To(HaveLen(1))
		Expect(d.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("nodeName", "control01"))
	})

	It("should include a ControlPlaneToleration when specified", func() {
		tol := corev1.Toleration{
			Key:      "foo",
			Operator: corev1.TolerationOpEqual,
			Value:    "bar",
			Effect:   corev1.TaintEffectNoExecute,
		}
		cfg.Installation.ControlPlaneTolerations = []corev1.Toleration{tol}

		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		resources, _ := component.Objects()
		d := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(d.Spec.Template.Spec.Tolerations).To(ContainElements(append(rmeta.TolerateControlPlane, tol)))
	})

	It("should include a ClusterRole and ClusterRoleBindings for reading webhook configuration", func() {
		expectedResources := []client.Object{
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "calico-audit-policy", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}},
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "tigera-ca-bundle", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-crds"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-access-calico-crds"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-tier-getter"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-tier-getter"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-tiered-policy-passthrough"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-tiered-policy-passthrough"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-uisettings-passthrough"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-uisettings-passthrough"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-extension-apiserver-auth-access"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-extension-apiserver-auth-access"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-delegate-auth"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-auth-reader", Namespace: "kube-system"}, TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&apiregv1.APIService{ObjectMeta: metav1.ObjectMeta{Name: "v3.projectcalico.org"}, TypeMeta: metav1.TypeMeta{Kind: "APIService", APIVersion: "apiregistration.k8s.io/v1"}},
			&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "calico-api", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},
			&policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "PodDisruptionBudget", APIVersion: "policy/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-uisettingsgroup-getter"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-uisettingsgroup-getter"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-ui-user"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-network-admin"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-webhook-reader"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-webhook-reader"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
		}

		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		rtest.ExpectResources(resources, expectedResources)

		// Should render the correct resources.
		cr := rtest.GetResource(resources, "calico-webhook-reader", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(len(cr.Rules)).To(Equal(1))
		Expect(len(cr.Rules[0].Resources)).To(Equal(2))
		Expect(cr.Rules[0].Resources[0]).To(Equal("mutatingwebhookconfigurations"))
		Expect(cr.Rules[0].Resources[1]).To(Equal("validatingwebhookconfigurations"))
		Expect(len(cr.Rules[0].Verbs)).To(Equal(3))
		Expect(cr.Rules[0].Verbs[0]).To(Equal("get"))
		Expect(cr.Rules[0].Verbs[1]).To(Equal("list"))
		Expect(cr.Rules[0].Verbs[2]).To(Equal("watch"))

		crb := rtest.GetResource(resources, "calico-apiserver-webhook-reader", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
		Expect(crb.RoleRef.Kind).To(Equal("ClusterRole"))
		Expect(crb.RoleRef.Name).To(Equal("calico-webhook-reader"))
		Expect(len(crb.Subjects)).To(Equal(1))
		Expect(crb.Subjects[0].Kind).To(Equal("ServiceAccount"))
		Expect(crb.Subjects[0].Name).To(Equal("calico-apiserver"))
		Expect(crb.Subjects[0].Namespace).To(Equal("calico-system"))
	})

	It("should set KUBERENETES_SERVICE_... variables if host networked", func() {
		cfg.K8SServiceEndpoint.Host = "k8shost"
		cfg.K8SServiceEndpoint.Port = "1234"
		cfg.ForceHostNetwork = true
		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		deploymentResource := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment")
		Expect(deploymentResource).ToNot(BeNil())

		deployment := deploymentResource.(*appsv1.Deployment)
		rtest.ExpectK8sServiceEpEnvVars(deployment.Spec.Template.Spec, "k8shost", "1234")
	})

	It("should set RecreateDeploymentStrategyType if host networked", func() {
		cfg.ForceHostNetwork = true
		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		resources, _ := component.Objects()
		d := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(d.Spec.Strategy.Type).To(Equal(appsv1.RecreateDeploymentStrategyType))
	})

	It("should add egress policy with Enterprise variant and K8SServiceEndpoint defined", func() {
		cfg.K8SServiceEndpoint.Host = "k8shost"
		cfg.K8SServiceEndpoint.Port = "1234"
		cfg.ForceHostNetwork = true

		component := render.APIServerPolicy(cfg)
		resources, _ := component.Objects()
		policyName := types.NamespacedName{Name: "calico-system.apiserver-access", Namespace: "calico-system"}
		policy := testutils.GetCalicoSystemPolicyFromResources(policyName, resources)
		Expect(policy).ToNot(BeNil())
		Expect(policy.Spec).ToNot(BeNil())
		Expect(policy.Spec.Egress).ToNot(BeNil())
		Expect(policy.Spec.Egress).To(ContainElement(calicov3.Rule{
			Action:   calicov3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: calicov3.EntityRule{
				Ports:   networkpolicy.Ports(1234),
				Domains: []string{"k8shost"},
			},
		}))
	})

	It("should add egress policy with Enterprise variant and K8SServiceEndpoint as IP defined", func() {
		cfg.K8SServiceEndpoint.Host = "169.169.169.169"
		cfg.K8SServiceEndpoint.Port = "4321"
		cfg.ForceHostNetwork = false

		component := render.APIServerPolicy(cfg)
		resources, _ := component.Objects()
		policyName := types.NamespacedName{Name: "calico-system.apiserver-access", Namespace: "calico-system"}
		policy := testutils.GetCalicoSystemPolicyFromResources(policyName, resources)
		Expect(policy).ToNot(BeNil())
		Expect(policy.Spec).ToNot(BeNil())
		Expect(policy.Spec.Egress).ToNot(BeNil())
		Expect(policy.Spec.Egress).To(ContainElement(calicov3.Rule{
			Action:   calicov3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: calicov3.EntityRule{
				Ports: networkpolicy.Ports(4321),
				Nets:  []string{"169.169.169.169/32"},
			},
		}))
	})

	It("should not set KUBERENETES_SERVICE_... variables if not host networked on Docker EE with proxy.local", func() {
		cfg.K8SServiceEndpoint.Host = "proxy.local"
		cfg.K8SServiceEndpoint.Port = "1234"
		cfg.Installation.KubernetesProvider = operatorv1.ProviderDockerEE

		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		deploymentResource := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment")
		Expect(deploymentResource).ToNot(BeNil())

		deployment := deploymentResource.(*appsv1.Deployment)
		rtest.ExpectNoK8sServiceEpEnvVars(deployment.Spec.Template.Spec)
	})

	It("should set KUBERENETES_SERVICE_... variables if not host networked on Docker EE with non-proxy address", func() {
		cfg.K8SServiceEndpointPodNetwork.Host = "k8shost"
		cfg.K8SServiceEndpointPodNetwork.Port = "1234"
		cfg.Installation.KubernetesProvider = operatorv1.ProviderDockerEE

		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		deploymentResource := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment")
		Expect(deploymentResource).ToNot(BeNil())

		deployment := deploymentResource.(*appsv1.Deployment)
		rtest.ExpectK8sServiceEpEnvVars(deployment.Spec.Template.Spec, "k8shost", "1234")
	})

	It("should render an API server with custom configuration with MCM enabled at startup", func() {
		cfg.ManagementCluster = managementCluster
		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())

		resources, _ := component.Objects()

		expectedResources := []client.Object{
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "calico-audit-policy", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}},
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "tigera-ca-bundle", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-crds"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-access-calico-crds"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-tier-getter"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-tier-getter"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-tiered-policy-passthrough"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-tiered-policy-passthrough"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-uisettings-passthrough"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-uisettings-passthrough"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-extension-apiserver-auth-access"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-extension-apiserver-auth-access"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-delegate-auth"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-auth-reader", Namespace: "kube-system"}, TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&apiregv1.APIService{ObjectMeta: metav1.ObjectMeta{Name: "v3.projectcalico.org"}, TypeMeta: metav1.TypeMeta{Kind: "APIService", APIVersion: "apiregistration.k8s.io/v1"}},
			&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "calico-api", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},
			&policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "PodDisruptionBudget", APIVersion: "policy/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-uisettingsgroup-getter"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-uisettingsgroup-getter"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-ui-user"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-network-admin"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: render.ManagedClustersWatchClusterRoleName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-webhook-reader"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-webhook-reader"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: render.APIServerSecretsRBACName, Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.APIServerSecretsRBACName, Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
		}

		rtest.ExpectResources(resources, expectedResources)

		By("Validating the newly created tunnel secret")
		tunnelSecret, err := certificatemanagement.CreateSelfSignedSecret(render.VoltronTunnelSecretName, common.OperatorNamespace(), "tigera-voltron", []string{"voltron"})
		Expect(err).ToNot(HaveOccurred())

		// Use the x509 package to validate that the cert was signed with the privatekey
		validateTunnelSecret(tunnelSecret)

		dep := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment")
		Expect(dep).ToNot(BeNil())

		By("Validating startup args")
		expectedArgs := []string{
			"--secure-port=5443",
			"--tls-private-key-file=/calico-apiserver-certs/tls.key",
			"--tls-cert-file=/calico-apiserver-certs/tls.crt",
			"--audit-policy-file=/etc/tigera/audit/policy.conf",
			"--audit-log-path=/var/log/calico/audit/tsee-audit.log",
			"--enable-managed-clusters-create-api=true",
			"--managementClusterAddr=example.com:1234",
		}
		Expect((dep.(*appsv1.Deployment)).Spec.Template.Spec.Containers[0].Args).To(ConsistOf(expectedArgs))
	})

	It("should render an API server with custom configuration with MCM enabled at restart", func() {
		cfg.ManagementCluster = managementCluster
		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())

		resources, _ := component.Objects()

		expected := []client.Object{
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "calico-audit-policy", Namespace: "calico-system"}},
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "tigera-ca-bundle", Namespace: "calico-system"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver", Namespace: "calico-system"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-crds"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-access-calico-crds"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-tier-getter"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-tier-getter"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-tiered-policy-passthrough"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-tiered-policy-passthrough"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-uisettings-passthrough"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-uisettings-passthrough"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-extension-apiserver-auth-access"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-extension-apiserver-auth-access"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-delegate-auth"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-auth-reader", Namespace: "kube-system"}},
			&apiregv1.APIService{ObjectMeta: metav1.ObjectMeta{Name: "v3.projectcalico.org"}},
			&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver", Namespace: "calico-system"}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "calico-api", Namespace: "calico-system"}},
			&policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver", Namespace: "calico-system"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-uisettingsgroup-getter"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-uisettingsgroup-getter"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-ui-user"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-network-admin"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: render.ManagedClustersWatchClusterRoleName}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-webhook-reader"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-webhook-reader"}},
			&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: render.APIServerSecretsRBACName, Namespace: "calico-system"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: render.APIServerSecretsRBACName, Namespace: "calico-system"}},
		}
		rtest.ExpectResources(resources, expected)

		dep := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment")
		Expect(dep).ToNot(BeNil())

		By("Validating startup args")
		expectedArgs := []string{
			"--secure-port=5443",
			"--tls-private-key-file=/calico-apiserver-certs/tls.key",
			"--tls-cert-file=/calico-apiserver-certs/tls.crt",
			"--audit-policy-file=/etc/tigera/audit/policy.conf",
			"--audit-log-path=/var/log/calico/audit/tsee-audit.log",
			"--enable-managed-clusters-create-api=true",
			"--managementClusterAddr=example.com:1234",
		}
		Expect((dep.(*appsv1.Deployment)).Spec.Template.Spec.Containers[0].Args).To(ConsistOf(expectedArgs))
	})

	It("should render an API server with signed ca bundles enabled", func() {
		cfg.ManagementCluster = managementCluster
		cfg.ManagementCluster.Spec.TLS = &operatorv1.TLS{
			SecretName: render.ManagerTLSSecretName,
		}
		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)

		resources, _ := component.Objects()

		dep := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment")
		Expect(dep).ToNot(BeNil())

		Expect((dep.(*appsv1.Deployment)).Spec.Template.Spec.Containers[0].Args).To(ContainElement("--managementClusterCAType=Public"))
		Expect((dep.(*appsv1.Deployment)).Spec.Template.Spec.Containers[0].Args).To(ContainElement(fmt.Sprintf("--tunnelSecretName=%s", render.ManagerTLSSecretName)))
	})

	It("should pass tunnelSecretName when TLS secret is not manager-tls", func() {
		cfg.ManagementCluster = managementCluster
		cfg.ManagementCluster.Spec.TLS = &operatorv1.TLS{
			SecretName: render.VoltronTunnelSecretName,
		}
		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)

		resources, _ := component.Objects()

		dep := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment")
		Expect(dep).ToNot(BeNil())

		args := (dep.(*appsv1.Deployment)).Spec.Template.Spec.Containers[0].Args
		Expect(args).To(ContainElement(fmt.Sprintf("--tunnelSecretName=%s", render.VoltronTunnelSecretName)))
		Expect(args).ToNot(ContainElement("--managementClusterCAType=Public"))
	})

	It("should add an init container if certificate management is enabled", func() {
		cfg.Installation.CertificateManagement = &operatorv1.CertificateManagement{SignerName: "a.b/c", CACert: cfg.TLSKeyPair.GetCertificatePEM()}
		certificateManager, err := certificatemanager.Create(cli, cfg.Installation, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())
		kp, err := certificateManager.GetOrCreateKeyPair(cli, render.CalicoAPIServerTLSSecretName, common.OperatorNamespace(), dnsNames)
		Expect(err).NotTo(HaveOccurred())
		qskp, err := certificateManager.GetOrCreateKeyPair(cli, render.CalicoAPIServerTLSSecretName, common.OperatorNamespace(), dnsNames)
		cfg.TLSKeyPair = kp
		cfg.QueryServerTLSKeyPairCertificateManagementOnly = qskp
		Expect(err).NotTo(HaveOccurred())
		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		resources, _ := component.Objects()
		expectedResources := []client.Object{
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "calico-audit-policy", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}},
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "tigera-ca-bundle", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-crds"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-access-calico-crds"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-tier-getter"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-tier-getter"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-tiered-policy-passthrough"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-tiered-policy-passthrough"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-uisettings-passthrough"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-uisettings-passthrough"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-extension-apiserver-auth-access"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-extension-apiserver-auth-access"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-delegate-auth"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-auth-reader", Namespace: "kube-system"}, TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&apiregv1.APIService{ObjectMeta: metav1.ObjectMeta{Name: "v3.projectcalico.org"}, TypeMeta: metav1.TypeMeta{Kind: "APIService", APIVersion: "apiregistration.k8s.io/v1"}},
			&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "calico-api", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},
			&policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "PodDisruptionBudget", APIVersion: "policy/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-uisettingsgroup-getter"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-uisettingsgroup-getter"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-ui-user"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tigera-network-admin"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-webhook-reader"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-webhook-reader"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
		}
		rtest.ExpectResources(resources, expectedResources)

		dep := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment")
		Expect(dep).ToNot(BeNil())
		deploy, ok := dep.(*appsv1.Deployment)
		Expect(ok).To(BeTrue())
		Expect(deploy.Spec.Template.Spec.InitContainers).To(HaveLen(2))
		Expect(deploy.Spec.Template.Spec.InitContainers[0].Name).To(Equal("calico-apiserver-certs-key-cert-provisioner"))
		rtest.ExpectEnv(deploy.Spec.Template.Spec.InitContainers[0].Env, "SIGNER", "a.b/c")
	})

	It("should not render PodAffinity when ControlPlaneReplicas is 1", func() {
		cfg.Installation.ControlPlaneReplicas = ptr.To[int32](1)
		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		resources, _ := component.Objects()

		deploy, ok := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(ok).To(BeTrue())
		Expect(deploy.Spec.Template.Spec.Affinity).To(BeNil())
	})

	It("should render PodAffinity when ControlPlaneReplicas is greater than 1", func() {
		cfg.Installation.ControlPlaneReplicas = ptr.To[int32](2)
		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		resources, _ := component.Objects()

		deploy, ok := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(ok).To(BeTrue())
		Expect(deploy.Spec.Template.Spec.Affinity).NotTo(BeNil())
		Expect(deploy.Spec.Template.Spec.Affinity).To(Equal(podaffinity.NewPodAntiAffinity("calico-apiserver", []string{"calico-system", "tigera-system", "calico-apiserver"})))
	})

	It("should render Linseed routing for the queryserver when ManagementClusterConnection is set", func() {
		cfg.ManagementClusterConnection = &operatorv1.ManagementClusterConnection{}
		cfg.ClusterDomain = "cluster.local"

		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		resources, _ := component.Objects()

		rb, ok := rtest.GetResource(resources, "tigera-linseed", "calico-system", "rbac.authorization.k8s.io", "v1", "RoleBinding").(*rbacv1.RoleBinding)
		Expect(ok).To(BeTrue(), "expected tigera-linseed RoleBinding in calico-system")
		Expect(rb.RoleRef.Name).To(Equal("tigera-linseed-secrets"))
		Expect(rb.Subjects).To(ConsistOf(rbacv1.Subject{
			Kind:      "ServiceAccount",
			Name:      render.GuardianServiceAccountName,
			Namespace: render.GuardianNamespace,
		}))

		deploy, ok := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(ok).To(BeTrue())
		var qs *corev1.Container
		for i := range deploy.Spec.Template.Spec.Containers {
			if deploy.Spec.Template.Spec.Containers[i].Name == "tigera-queryserver" {
				qs = &deploy.Spec.Template.Spec.Containers[i]
			}
		}
		Expect(qs).NotTo(BeNil())
		Expect(qs.Env).To(ContainElement(corev1.EnvVar{Name: "LINSEED_URL", Value: "https://guardian.calico-system.svc"}))
		Expect(qs.Env).To(ContainElement(corev1.EnvVar{Name: "CLUSTER_ID", Value: ""}))
		Expect(qs.Env).To(ContainElement(corev1.EnvVar{Name: "LINSEED_TOKEN", Value: "/var/run/secrets/tigera.io/linseed/token"}))
		Expect(qs.VolumeMounts).To(ContainElement(corev1.VolumeMount{
			Name:      render.LinseedTokenVolumeName,
			MountPath: render.LinseedVolumeMountPath,
		}))

		var tokenVol *corev1.Volume
		for i := range deploy.Spec.Template.Spec.Volumes {
			if deploy.Spec.Template.Spec.Volumes[i].Name == render.LinseedTokenVolumeName {
				tokenVol = &deploy.Spec.Template.Spec.Volumes[i]
			}
		}
		Expect(tokenVol).NotTo(BeNil())
		Expect(tokenVol.Secret).NotTo(BeNil())
		Expect(tokenVol.Secret.SecretName).To(Equal("calico-apiserver-tigera-linseed-token"))
	})

	Context("calico-system rendering", func() {
		policyName := types.NamespacedName{Name: "calico-system.apiserver-access", Namespace: "calico-system"}

		DescribeTable("should render calico-system policy",
			func(scenario testutils.CalicoSystemScenario) {
				cfg.OpenShift = scenario.OpenShift
				if scenario.ManagedCluster {
					cfg.ManagementClusterConnection = &operatorv1.ManagementClusterConnection{}
				} else {
					cfg.ManagementClusterConnection = nil
				}

				component := render.APIServerPolicy(cfg)
				resources, _ := component.Objects()

				policy := testutils.GetCalicoSystemPolicyFromResources(policyName, resources)
				expectedPolicy := testutils.SelectPolicyByProvider(scenario, apiServerPolicy, apiServerPolicyForOCP)
				Expect(policy).To(Equal(expectedPolicy))
			},
			Entry("for management/standalone, kube-dns", testutils.CalicoSystemScenario{ManagedCluster: false, OpenShift: false}),
			Entry("for management/standalone, openshift-dns", testutils.CalicoSystemScenario{ManagedCluster: false, OpenShift: true}),
			Entry("for managed, kube-dns", testutils.CalicoSystemScenario{ManagedCluster: true, OpenShift: false}),
			Entry("for managed, openshift-dns", testutils.CalicoSystemScenario{ManagedCluster: true, OpenShift: true}),
		)
	})

	Context("With APIServer Deployment overrides", func() {
		rr1 := corev1.ResourceRequirements{
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

		rr2 := corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("250m"),
				corev1.ResourceMemory: resource.MustParse("64Mi"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("500m"),
				corev1.ResourceMemory: resource.MustParse("500Mi"),
			},
		}

		It("should handle APIServerDeployment overrides", func() {
			var minReadySeconds int32 = 20

			affinity := &corev1.Affinity{
				NodeAffinity: &corev1.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
						NodeSelectorTerms: []corev1.NodeSelectorTerm{{
							MatchExpressions: []corev1.NodeSelectorRequirement{{
								Key:      "custom-affinity-key",
								Operator: corev1.NodeSelectorOpExists,
							}},
						}},
					},
				},
			}
			toleration := corev1.Toleration{
				Key:      "foo",
				Operator: corev1.TolerationOpEqual,
				Value:    "bar",
			}

			apiServerPort := operatorv1.APIServerDeploymentContainerPort{
				Name:          render.APIServerPortName,
				ContainerPort: 1111,
			}
			queryServerPort := operatorv1.APIServerDeploymentContainerPort{
				Name:          render.QueryServerPortName,
				ContainerPort: 2222,
			}
			l7AdmCtrlPort := operatorv1.APIServerDeploymentContainerPort{
				Name:          render.L7AdmissionControllerPortName,
				ContainerPort: 3333,
			}

			sidecarEnabled := operatorv1.SidecarEnabled
			cfg.ApplicationLayer = &operatorv1.ApplicationLayer{
				Spec: operatorv1.ApplicationLayerSpec{
					SidecarInjection: &sidecarEnabled,
				},
			}

			cfg.APIServer.APIServerDeployment = &operatorv1.APIServerDeployment{
				Metadata: &operatorv1.Metadata{
					Labels:      map[string]string{"top-level": "label1"},
					Annotations: map[string]string{"top-level": "annot1"},
				},
				Spec: &operatorv1.APIServerDeploymentSpec{
					MinReadySeconds: &minReadySeconds,
					Template: &operatorv1.APIServerDeploymentPodTemplateSpec{
						Metadata: &operatorv1.Metadata{
							Labels:      map[string]string{"template-level": "label2"},
							Annotations: map[string]string{"template-level": "annot2"},
						},
						Spec: &operatorv1.APIServerDeploymentPodSpec{
							Containers: []operatorv1.APIServerDeploymentContainer{
								{
									Name:      "calico-apiserver",
									Resources: &rr1,
									Ports:     []operatorv1.APIServerDeploymentContainerPort{apiServerPort},
								},
								{
									Name:      "tigera-queryserver",
									Resources: &rr2,
									Ports:     []operatorv1.APIServerDeploymentContainerPort{queryServerPort},
								},
								{
									Name:      "calico-l7-admission-controller",
									Resources: &rr2,
									Ports:     []operatorv1.APIServerDeploymentContainerPort{l7AdmCtrlPort},
								},
							},
							InitContainers: []operatorv1.APIServerDeploymentInitContainer{
								{
									Name:      "calico-apiserver-certs-key-cert-provisioner",
									Resources: &rr2,
								},
							},
							NodeSelector: map[string]string{
								"custom-node-selector": "value",
							},
							TopologySpreadConstraints: []corev1.TopologySpreadConstraint{
								{
									MaxSkew: 1,
								},
							},
							Affinity:    affinity,
							Tolerations: []corev1.Toleration{toleration},
						},
					},
				},
			}
			// Enable certificate management.
			cfg.Installation.CertificateManagement = &operatorv1.CertificateManagement{SignerName: "a.b/c", CACert: cfg.TLSKeyPair.GetCertificatePEM()}
			certificateManager, err := certificatemanager.Create(cli, cfg.Installation, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
			Expect(err).NotTo(HaveOccurred())

			// Create and add the TLS keypair so the initContainer is rendered.
			dnsNames := dns.GetServiceDNSNames(render.APIServerServiceName, render.APIServerNamespace, clusterDomain)
			kp, err := certificateManager.GetOrCreateKeyPair(cli, render.CalicoAPIServerTLSSecretName, common.OperatorNamespace(), dnsNames)
			Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
			cfg.TLSKeyPair = kp

			qsKP, err := certificateManager.GetOrCreateKeyPair(cli, render.CalicoAPIServerTLSSecretName, common.OperatorNamespace(), dnsNames)
			Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
			cfg.QueryServerTLSKeyPairCertificateManagementOnly = qsKP

			component, err := render.APIServer(cfg)
			Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
			resources, _ := component.Objects()

			d, ok := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue())

			// API server has apiserver: true label
			Expect(d.Labels).To(HaveLen(2))
			Expect(d.Labels["apiserver"]).To(Equal("true"))
			Expect(d.Labels["top-level"]).To(Equal("label1"))
			Expect(d.Annotations).To(HaveLen(1))
			Expect(d.Annotations["top-level"]).To(Equal("annot1"))

			Expect(d.Spec.MinReadySeconds).To(Equal(minReadySeconds))

			// At runtime, the operator will also add some standard labels to the
			// deployment such as "k8s-app=calico-apiserver". But the APIServer
			// deployment object produced by the render will have no labels so we expect just the one
			// provided.
			Expect(d.Spec.Template.Labels).To(HaveLen(2))
			Expect(d.Spec.Template.Labels["apiserver"]).To(Equal("true"))
			Expect(d.Spec.Template.Labels["template-level"]).To(Equal("label2"))

			// With the default instance we expect 2 template-level annotations
			// - 1 added by the operator by default
			// - 1 added by the calicoNodeDaemonSet override
			Expect(d.Spec.Template.Annotations).To(HaveLen(2))
			Expect(d.Spec.Template.Annotations).To(HaveKey("tigera-operator.hash.operator.tigera.io/calico-apiserver-certs"))
			Expect(d.Spec.Template.Annotations["template-level"]).To(Equal("annot2"))

			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(3))
			containersFound := 0
			for _, c := range d.Spec.Template.Spec.Containers {
				switch c.Name {
				case "calico-apiserver":
					Expect(c.Resources).To(Equal(rr1))
					Expect(c.Ports[0].Name).To(Equal(apiServerPort.Name))
					Expect(c.Ports[0].ContainerPort).To(Equal(apiServerPort.ContainerPort))

					Expect(c.Args[0]).To(ContainSubstring(fmt.Sprintf("--secure-port=%d", apiServerPort.ContainerPort)))
					containersFound++
				case "tigera-queryserver":
					Expect(c.Resources).To(Equal(rr2))
					Expect(c.Ports[0].Name).To(Equal(queryServerPort.Name))
					Expect(c.Ports[0].ContainerPort).To(Equal(queryServerPort.ContainerPort))

					Expect(c.Env[1].Name).To(Equal("LISTEN_ADDR"))
					Expect(c.Env[1].Value).To(Equal(fmt.Sprintf(":%d", queryServerPort.ContainerPort)))
					containersFound++
				case "calico-l7-admission-controller":
					Expect(c.Resources).To(Equal(rr2))
					Expect(c.Ports[0].Name).To(Equal(l7AdmCtrlPort.Name))
					Expect(c.Ports[0].ContainerPort).To(Equal(l7AdmCtrlPort.ContainerPort))

					Expect(c.Env[4].Name).To(Equal("L7ADMCTRL_LISTENADDR"))
					Expect(c.Env[4].Value).To(Equal(fmt.Sprintf(":%d", l7AdmCtrlPort.ContainerPort)))
					containersFound++
				}
			}
			Expect(containersFound).To(Equal(3))

			Expect(d.Spec.Template.Spec.InitContainers).To(HaveLen(2))
			Expect(d.Spec.Template.Spec.InitContainers[0].Name).To(Equal("calico-apiserver-certs-key-cert-provisioner"))
			Expect(d.Spec.Template.Spec.InitContainers[0].Resources).To(Equal(rr2))

			Expect(d.Spec.Template.Spec.NodeSelector).To(HaveLen(1))
			Expect(d.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("custom-node-selector", "value"))

			Expect(d.Spec.Template.Spec.TopologySpreadConstraints).To(HaveLen(1))
			Expect(d.Spec.Template.Spec.TopologySpreadConstraints[0].MaxSkew).To(Equal(int32(1)))

			Expect(d.Spec.Template.Spec.Tolerations).To(HaveLen(1))
			Expect(d.Spec.Template.Spec.Tolerations[0]).To(Equal(toleration))

			// Check the Service configuration
			svc := rtest.GetResource(resources, "calico-api", "calico-system", "", "v1", "Service").(*corev1.Service)
			Expect(svc.Spec.Ports).To(HaveLen(3))
			servicesFound := 0
			for _, p := range svc.Spec.Ports {
				switch p.Name {
				case render.APIServerPortName:
					Expect(p.Port).To(Equal(int32(443)))
					Expect(p.TargetPort.IntVal).To(Equal(apiServerPort.ContainerPort))
					servicesFound++
				case render.QueryServerPortName:
					Expect(p.Port).To(Equal(int32(8080)))
					Expect(p.TargetPort.IntVal).To(Equal(queryServerPort.ContainerPort))
					servicesFound++
				case render.L7AdmissionControllerPortName:
					Expect(p.Port).To(Equal(int32(6443)))
					Expect(p.TargetPort.IntVal).To(Equal(l7AdmCtrlPort.ContainerPort))
					servicesFound++
				}
			}
			Expect(servicesFound).To(Equal(3))
		})

		It("should override a ControlPlaneNodeSelector when specified", func() {
			cfg.Installation.ControlPlaneNodeSelector = map[string]string{"nodeName": "control01"}

			cfg.APIServer.APIServerDeployment = &operatorv1.APIServerDeployment{
				Spec: &operatorv1.APIServerDeploymentSpec{
					Template: &operatorv1.APIServerDeploymentPodTemplateSpec{
						Spec: &operatorv1.APIServerDeploymentPodSpec{
							NodeSelector: map[string]string{
								"custom-node-selector": "value",
							},
						},
					},
				},
			}
			component, err := render.APIServer(cfg)
			Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()
			d, ok := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue())
			// nodeSelectors are merged
			Expect(d.Spec.Template.Spec.NodeSelector).To(HaveLen(2))
			Expect(d.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("nodeName", "control01"))
			Expect(d.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("custom-node-selector", "value"))
		})

		It("should override ControlPlaneTolerations when specified", func() {
			cfg.Installation.ControlPlaneTolerations = rmeta.TolerateControlPlane

			tol := corev1.Toleration{
				Key:      "foo",
				Operator: corev1.TolerationOpEqual,
				Value:    "bar",
				Effect:   corev1.TaintEffectNoExecute,
			}

			cfg.APIServer.APIServerDeployment = &operatorv1.APIServerDeployment{
				Spec: &operatorv1.APIServerDeploymentSpec{
					Template: &operatorv1.APIServerDeploymentPodTemplateSpec{
						Spec: &operatorv1.APIServerDeploymentPodSpec{
							Tolerations: []corev1.Toleration{tol},
						},
					},
				},
			}
			component, err := render.APIServer(cfg)
			Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()
			d, ok := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue())
			Expect(d.Spec.Template.Spec.Tolerations).To(HaveLen(1))
			Expect(d.Spec.Template.Spec.Tolerations).To(ConsistOf(tol))
		})

		It("should disable ValidatingAdmissionPolicy on older k8s versions", func() {
			cfg.KubernetesVersion = &common.VersionInfo{
				Major: 1,
				Minor: 28,
			}
			component, err := render.APIServer(cfg)
			Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
			resources, _ := component.Objects()
			d := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(d.Spec.Template.Spec.Containers[0].Args).To(ConsistOf([]string{
				"--secure-port=5443",
				"--tls-private-key-file=/calico-apiserver-certs/tls.key",
				"--tls-cert-file=/calico-apiserver-certs/tls.crt",
				"--audit-policy-file=/etc/tigera/audit/policy.conf",
				"--audit-log-path=/var/log/calico/audit/tsee-audit.log",
				"--enable-validating-admission-policy=false",
			}))
		})
	})
})

func verifyAPIService(service *apiregv1.APIService, enterprise bool, clusterDomain string) {
	Expect(service.Name).To(Equal("v3.projectcalico.org"))
	Expect(service.Spec.Group).To(Equal("projectcalico.org"))
	Expect(service.Spec.Version).To(Equal("v3"))
	Expect(service.Spec.GroupPriorityMinimum).To(BeEquivalentTo(1500))
	Expect(service.Spec.VersionPriority).To(BeEquivalentTo(200))
	Expect(service.Spec.InsecureSkipTLSVerify).To(BeFalse())

	ca := service.Spec.CABundle

	expectedDNSNames := []string{
		"calico-api",
		"calico-api.calico-system",
		"calico-api.calico-system.svc",
		"calico-api.calico-system.svc." + clusterDomain,
	}

	test.VerifyCertSANs(ca, expectedDNSNames...)
}

func validateTunnelSecret(voltronSecret *corev1.Secret) {
	var newCert *x509.Certificate

	cert := voltronSecret.Data[corev1.TLSCertKey]
	key := voltronSecret.Data[corev1.TLSPrivateKeyKey]
	_, err := tls.X509KeyPair(cert, key)
	Expect(err).ShouldNot(HaveOccurred())

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(cert))
	Expect(ok).To(BeTrue())

	block, _ := pem.Decode([]byte(cert))
	Expect(err).ShouldNot(HaveOccurred())
	Expect(block).To(Not(BeNil()))

	newCert, err = x509.ParseCertificate(block.Bytes)
	Expect(err).ShouldNot(HaveOccurred())

	opts := x509.VerifyOptions{
		DNSName: "voltron",
		Roots:   roots,
	}

	_, err = newCert.Verify(opts)
	Expect(err).ShouldNot(HaveOccurred())

	opts = x509.VerifyOptions{
		DNSName:     "voltron",
		Roots:       x509.NewCertPool(),
		CurrentTime: time.Now().Add(crypto.DefaultCACertificateLifetimeDuration + 24*time.Hour),
	}
	_, err = newCert.Verify(opts)
	Expect(err).Should(HaveOccurred())
}

var (
	uiUserPolicyRules = []rbacv1.PolicyRule{
		{
			APIGroups: []string{
				"projectcalico.org",
				"networking.k8s.io",
				"extensions",
				"",
			},
			Resources: []string{
				"tiers",
				"networkpolicies",
				"tier.networkpolicies",
				"globalnetworkpolicies",
				"tier.globalnetworkpolicies",
				"namespaces",
				"globalnetworksets",
				"networksets",
				"managedclusters",
				"stagedglobalnetworkpolicies",
				"tier.stagedglobalnetworkpolicies",
				"stagednetworkpolicies",
				"tier.stagednetworkpolicies",
				"stagedkubernetesnetworkpolicies",
				"policyrecommendationscopes",
			},
			Verbs: []string{"watch", "list"},
		},
		{
			APIGroups: []string{"policy.networking.k8s.io"},
			Resources: []string{
				"clusternetworkpolicies",
				"adminnetworkpolicies",
				"baselineadminnetworkpolicies",
			},
			Verbs: []string{"watch", "list"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"packetcaptures/files"},
			Verbs:     []string{"get"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"packetcaptures"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"list"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"serviceaccounts"},
			Verbs:     []string{"list"},
		},
		{
			APIGroups:     []string{""},
			Resources:     []string{"configmaps"},
			ResourceNames: []string{"coreruleset-default"},
			Verbs:         []string{"get"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"services/proxy"},
			ResourceNames: []string{
				"https:calico-api:8080", "calico-node-prometheus:9090",
			},
			Verbs: []string{"get", "create"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"tiers"},
			Verbs:     []string{"get"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"globalreports"},
			Verbs:     []string{"get", "list"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"globalreporttypes"},
			Verbs:     []string{"get"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"clusterinformations"},
			Verbs:     []string{"get", "list"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"hostendpoints"},
			Verbs:     []string{"get", "list"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{
				"alertexceptions",
				"globalalerts",
				"globalalerts/status",
				"globalalerttemplates",
				"globalthreatfeeds",
				"globalthreatfeeds/status",
				"securityeventwebhooks",
			},
			Verbs: []string{"get", "watch", "list"},
		},
		{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"uisettingsgroups"},
			Verbs:         []string{"get"},
			ResourceNames: []string{"cluster-settings", "user-settings"},
		},
		{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"uisettingsgroups/data"},
			Verbs:         []string{"get", "list", "watch"},
			ResourceNames: []string{"cluster-settings"},
		},
		{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"uisettingsgroups/data"},
			Verbs:         []string{"*"},
			ResourceNames: []string{"user-settings"},
		},
		{
			APIGroups: []string{"lma.tigera.io"},
			Resources: []string{"*"},
			ResourceNames: []string{
				"flows", "audit*", "l7", "events", "dns", "waf", "kibana_login", "recommendations",
			},
			Verbs: []string{"get"},
		},
		{
			APIGroups: []string{"operator.tigera.io"},
			Resources: []string{"applicationlayers", "packetcaptureapis", "compliances", "intrusiondetections"},
			Verbs:     []string{"get"},
		},
		{
			APIGroups: []string{"apps"},
			Resources: []string{"deployments"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"services"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"felixconfigurations"},
			Verbs:     []string{"get", "list"},
		},
		{
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"securityeventwebhooks"},
			Verbs:     []string{"get", "list"},
		},
	}
	networkAdminPolicyRules = []rbacv1.PolicyRule{
		{
			APIGroups: []string{
				"projectcalico.org",
				"networking.k8s.io",
				"extensions",
			},
			Resources: []string{
				"tiers",
				"networkpolicies",
				"tier.networkpolicies",
				"globalnetworkpolicies",
				"tier.globalnetworkpolicies",
				"stagedglobalnetworkpolicies",
				"tier.stagedglobalnetworkpolicies",
				"stagednetworkpolicies",
				"tier.stagednetworkpolicies",
				"stagedkubernetesnetworkpolicies",
				"globalnetworksets",
				"networksets",
				"managedclusters",
				"packetcaptures",
				"policyrecommendationscopes",
			},
			Verbs: []string{"create", "update", "delete", "patch", "get", "watch", "list"},
		},
		{
			APIGroups: []string{
				"policy.networking.k8s.io",
			},
			Resources: []string{
				"clusternetworkpolicies",
				"adminnetworkpolicies",
				"baselineadminnetworkpolicies",
			},
			Verbs: []string{"create", "update", "delete", "patch", "get", "watch", "list"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"packetcaptures/files"},
			Verbs:     []string{"get", "delete"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"namespaces"},
			Verbs:     []string{"watch", "list"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"list"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"serviceaccounts"},
			Verbs:     []string{"list"},
		},
		{
			APIGroups:     []string{""},
			Resources:     []string{"configmaps"},
			ResourceNames: []string{"coreruleset-default"},
			Verbs:         []string{"get"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"services/proxy"},
			ResourceNames: []string{
				"https:calico-api:8080", "calico-node-prometheus:9090",
			},
			Verbs: []string{"get", "create"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"globalreports"},
			Verbs:     []string{"*"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"globalreports/status"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"globalreporttypes"},
			Verbs:     []string{"get"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"clusterinformations"},
			Verbs:     []string{"get", "list"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"hostendpoints"},
			Verbs:     []string{"get", "list"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{
				"alertexceptions",
				"globalalerts",
				"globalalerts/status",
				"globalalerttemplates",
				"globalthreatfeeds",
				"globalthreatfeeds/status",
				"securityeventwebhooks",
			},
			Verbs: []string{"create", "update", "delete", "patch", "get", "watch", "list"},
		},
		{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"uisettingsgroups"},
			Verbs:         []string{"get", "patch", "update"},
			ResourceNames: []string{"cluster-settings", "user-settings"},
		},
		{
			APIGroups:     []string{"projectcalico.org"},
			Resources:     []string{"uisettingsgroups/data"},
			Verbs:         []string{"*"},
			ResourceNames: []string{"cluster-settings", "user-settings"},
		},
		{
			APIGroups: []string{"lma.tigera.io"},
			Resources: []string{"*"},
			ResourceNames: []string{
				"flows", "audit*", "l7", "events", "dns", "waf", "kibana_login", "elasticsearch_superuser", "recommendations",
			},
			Verbs: []string{"get"},
		},
		{
			APIGroups: []string{"operator.tigera.io"},
			Resources: []string{"applicationlayers", "packetcaptureapis", "compliances", "intrusiondetections"},
			Verbs:     []string{"get", "update", "patch", "create", "delete"},
		},
		{
			APIGroups: []string{"apps"},
			Resources: []string{"deployments"},
			Verbs:     []string{"get", "list", "watch", "patch"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"services"},
			Verbs:     []string{"get", "list", "watch", "patch"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"felixconfigurations"},
			Verbs:     []string{"get", "list"},
		},
		{
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"securityeventwebhooks"},
			Verbs:     []string{"get", "list", "update", "patch", "create", "delete"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"secrets"},
			Verbs:     []string{"create"},
		},
		{
			APIGroups:     []string{""},
			Resources:     []string{"secrets"},
			ResourceNames: []string{"webhooks-secret"},
			Verbs:         []string{"patch"},
		},
	}
)

var _ = Describe("API server rendering tests (Calico)", func() {
	var instance *operatorv1.InstallationSpec
	var apiserver *operatorv1.APIServerSpec
	var cfg *render.APIServerConfiguration
	var certificateManager certificatemanager.CertificateManager
	var cli client.Client

	BeforeEach(func() {
		instance = &operatorv1.InstallationSpec{
			ControlPlaneReplicas: ptr.To[int32](2),
			Registry:             "testregistry.com/",
			Variant:              operatorv1.Calico,
		}
		apiserver = &operatorv1.APIServerSpec{}
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
		var err error
		certificateManager, err = certificatemanager.Create(cli, nil, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())
		dnsNames := dns.GetServiceDNSNames(render.APIServerServiceName, render.APIServerNamespace, clusterDomain)
		kp, err := certificateManager.GetOrCreateKeyPair(cli, render.CalicoAPIServerTLSSecretName, common.OperatorNamespace(), dnsNames)
		Expect(err).NotTo(HaveOccurred())

		cfg = &render.APIServerConfiguration{
			RequiresAggregationServer: true,
			K8SServiceEndpoint:        k8sapi.ServiceEndpoint{},
			Installation:              instance,
			APIServer:                 apiserver,
			OpenShift:                 true,
			TLSKeyPair:                kp,
		}
	})

	DescribeTable("should render an API server with default configuration", func(clusterDomain string) {
		expectedResources := []client.Object{
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-crds"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-access-calico-crds"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-tier-getter"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-tier-getter"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-tiered-policy-passthrough"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-tiered-policy-passthrough"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-extension-apiserver-auth-access"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-extension-apiserver-auth-access"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-delegate-auth"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-auth-reader", Namespace: "kube-system"}, TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&apiregv1.APIService{ObjectMeta: metav1.ObjectMeta{Name: "v3.projectcalico.org"}, TypeMeta: metav1.TypeMeta{Kind: "APIService", APIVersion: "apiregistration.k8s.io/v1"}},
			&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "calico-api", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},
			&policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{Kind: "PodDisruptionBudget", APIVersion: "policy/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-webhook-reader"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-webhook-reader"}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
		}

		dnsNames := dns.GetServiceDNSNames(render.APIServerServiceName, render.APIServerNamespace, clusterDomain)
		kp, err := certificateManager.GetOrCreateKeyPair(cli, render.CalicoAPIServerTLSSecretName, common.OperatorNamespace(), dnsNames)
		Expect(err).NotTo(HaveOccurred())
		cfg.TLSKeyPair = kp
		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())

		resources, deleteResources := component.Objects()

		rtest.ExpectResources(resources, expectedResources)
		rtest.ExpectResourceInList(deleteResources, "allow-apiserver", "calico-system", "networking.k8s.io", "v1", "NetworkPolicy")

		apiService, ok := rtest.GetResource(resources, "v3.projectcalico.org", "", "apiregistration.k8s.io", "v1", "APIService").(*apiregv1.APIService)
		Expect(ok).To(BeTrue(), "Expected v1.APIService")
		verifyAPIService(apiService, false, clusterDomain)

		d := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(d.Name).To(Equal("calico-apiserver"))
		Expect(len(d.Labels)).To(Equal(1))
		Expect(d.Labels).To(HaveKeyWithValue("apiserver", "true"))
		Expect(*d.Spec.Replicas).To(BeEquivalentTo(2))
		Expect(d.Spec.Strategy.Type).To(Equal(appsv1.RollingUpdateDeploymentStrategyType))
		Expect(len(d.Spec.Selector.MatchLabels)).To(Equal(1))
		Expect(d.Spec.Selector.MatchLabels).To(HaveKeyWithValue("apiserver", "true"))
		Expect(d.Spec.Template.Name).To(Equal("calico-apiserver"))
		Expect(d.Spec.Template.Namespace).To(Equal("calico-system"))
		Expect(len(d.Spec.Template.Labels)).To(Equal(1))
		Expect(d.Spec.Template.Labels).To(HaveKeyWithValue("apiserver", "true"))
		Expect(d.Spec.Template.Spec.ServiceAccountName).To(Equal("calico-apiserver"))
		Expect(d.Spec.Template.Spec.Tolerations).To(ConsistOf(rmeta.TolerateControlPlane))
		Expect(d.Spec.Template.Spec.ImagePullSecrets).To(BeEmpty())
		Expect(len(d.Spec.Template.Spec.Containers)).To(Equal(1))
		Expect(d.Spec.Template.Spec.Containers[0].Name).To(Equal("calico-apiserver"))
		Expect(d.Spec.Template.Spec.Containers[0].Image).To(Equal(
			fmt.Sprintf("testregistry.com/%s%s:%s", components.CalicoImagePath, components.ComponentCalicoAPIServer.Image, components.ComponentCalicoAPIServer.Version),
		))

		expectedArgs := []string{
			"--secure-port=5443",
			"--tls-private-key-file=/calico-apiserver-certs/tls.key",
			"--tls-cert-file=/calico-apiserver-certs/tls.crt",
		}
		Expect(d.Spec.Template.Spec.Containers[0].Args).To(ConsistOf(expectedArgs))
		Expect(len(d.Spec.Template.Spec.Containers[0].Env)).To(Equal(2))
		Expect(d.Spec.Template.Spec.Containers[0].Env[0].Name).To(Equal("DATASTORE_TYPE"))
		Expect(d.Spec.Template.Spec.Containers[0].Env[0].Value).To(Equal("kubernetes"))
		Expect(d.Spec.Template.Spec.Containers[0].Env[0].ValueFrom).To(BeNil())
		Expect(d.Spec.Template.Spec.Containers[0].Env[1].Name).To(Equal("LOG_LEVEL"))
		Expect(d.Spec.Template.Spec.Containers[0].Env[1].Value).To(Equal("info"))
		Expect(d.Spec.Template.Spec.Containers[0].Env[1].ValueFrom).To(BeNil())

		Expect(len(d.Spec.Template.Spec.Containers[0].VolumeMounts)).To(Equal(1))

		Expect(d.Spec.Template.Spec.Containers[0].ReadinessProbe.HTTPGet.Path).To(Equal("/readyz"))
		Expect(d.Spec.Template.Spec.Containers[0].ReadinessProbe.HTTPGet.Port.String()).To(BeEquivalentTo("5443"))
		Expect(d.Spec.Template.Spec.Containers[0].ReadinessProbe.HTTPGet.Scheme).To(BeEquivalentTo("HTTPS"))
		Expect(d.Spec.Template.Spec.Containers[0].ReadinessProbe.PeriodSeconds).To(BeEquivalentTo(60))

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

		Expect(len(d.Spec.Template.Spec.Volumes)).To(Equal(1))

		clusterRole := rtest.GetResource(resources, "tigera-network-admin", "", "rbac.authorization.k8s.io", "v1", "ClusterRole")
		Expect(clusterRole).To(BeNil())

		clusterRole = rtest.GetResource(resources, "tigera-ui-user", "", "rbac.authorization.k8s.io", "v1", "ClusterRole")
		Expect(clusterRole).To(BeNil())

		clusterRoleBinding := rtest.GetResource(resources, "calico-extension-apiserver-auth-access", "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
		Expect(clusterRoleBinding.RoleRef.Name).To(Equal("calico-extension-apiserver-auth-access"))

		cr := rtest.GetResource(resources, "calico-tiered-policy-passthrough", "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		var tieredPolicyRules []string
		for _, rule := range cr.Rules {
			tieredPolicyRules = append(tieredPolicyRules, rule.Resources...)
		}
		Expect(tieredPolicyRules).To(ContainElements("networkpolicies", "globalnetworkpolicies"))
		Expect(tieredPolicyRules).ToNot(ContainElements("stagednetworkpolicies", "stagedglobalnetworkpolicies"))
	},
		Entry("default cluster domain", dns.DefaultClusterDomain),
		Entry("custom cluster domain", "custom-domain.internal"),
	)

	It("should not render deployment for OSS without aggregation server", func() {
		cfg.RequiresAggregationServer = false

		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, deleteResources := component.Objects()

		// Should not include deployment, service, SA, or PDB.
		Expect(rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment")).To(BeNil())
		Expect(rtest.GetResource(resources, "calico-api", "calico-system", "", "v1", "Service")).To(BeNil())
		Expect(rtest.GetResource(resources, "calico-apiserver", "calico-system", "", "v1", "ServiceAccount")).To(BeNil())
		Expect(rtest.GetResource(resources, "calico-apiserver", "calico-system", "policy", "v1", "PodDisruptionBudget")).To(BeNil())

		// Should still include RBAC.
		Expect(rtest.GetResource(resources, "calico-crds", "", "rbac.authorization.k8s.io", "v1", "ClusterRole")).ToNot(BeNil())
		Expect(rtest.GetResource(resources, "calico-webhook-reader", "", "rbac.authorization.k8s.io", "v1", "ClusterRole")).ToNot(BeNil())

		// Deployment and related objects should be in the delete list.
		rtest.ExpectResourceInList(deleteResources, "calico-apiserver", "calico-system", "", "v1", "ServiceAccount")
		rtest.ExpectResourceInList(deleteResources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment")
		rtest.ExpectResourceInList(deleteResources, "calico-api", "calico-system", "", "v1", "Service")
		rtest.ExpectResourceInList(deleteResources, "calico-apiserver", "calico-system", "policy", "v1", "PodDisruptionBudget")
	})

	It("should render an API server with custom configuration", func() {
		expectedResources := []client.Object{
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "ServiceAccount"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-crds"}, TypeMeta: metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-access-calico-crds"}, TypeMeta: metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRoleBinding"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-tier-getter"}, TypeMeta: metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-tier-getter"}, TypeMeta: metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRoleBinding"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-tiered-policy-passthrough"}, TypeMeta: metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-tiered-policy-passthrough"}, TypeMeta: metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRoleBinding"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-extension-apiserver-auth-access"}, TypeMeta: metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-extension-apiserver-auth-access"}, TypeMeta: metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRoleBinding"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-delegate-auth"}, TypeMeta: metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRoleBinding"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-auth-reader", Namespace: "kube-system"}, TypeMeta: metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "RoleBinding"}},
			&apiregv1.APIService{ObjectMeta: metav1.ObjectMeta{Name: "v3.projectcalico.org"}, TypeMeta: metav1.TypeMeta{APIVersion: "apiregistration.k8s.io/v1", Kind: "APIService"}},
			&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "calico-api", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Service"}},
			&policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver", Namespace: "calico-system"}, TypeMeta: metav1.TypeMeta{APIVersion: "policy/v1", Kind: "PodDisruptionBudget"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "calico-webhook-reader"}, TypeMeta: metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "calico-apiserver-webhook-reader"}, TypeMeta: metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRoleBinding"}},
		}

		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, deleteResources := component.Objects()

		// Should render the correct resources.
		By("Checking each expected resource is actually rendered")
		for _, e := range expectedResources {
			gvk := e.GetObjectKind().GroupVersionKind()
			rtest.ExpectResourceInList(resources, e.GetName(), e.GetNamespace(), gvk.Group, gvk.Version, gvk.Kind)
		}

		By("Checking each rendered resource is actually expected")
		for _, r := range resources {
			gvk := r.GetObjectKind().GroupVersionKind()
			rtest.ExpectResourceInList(expectedResources, r.GetName(), r.GetNamespace(), gvk.Group, gvk.Version, gvk.Kind)
		}

		rtest.ExpectResourceInList(deleteResources, "allow-apiserver", "calico-system", "networking.k8s.io", "v1", "NetworkPolicy")

		// Expect same number as above
		Expect(len(resources)).To(Equal(len(expectedResources)))

		dep := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment")
		rtest.ExpectResourceTypeAndObjectMetadata(dep, "calico-apiserver", "calico-system", "apps", "v1", "Deployment")
		d := dep.(*appsv1.Deployment)
		Expect(len(d.Spec.Template.Spec.Volumes)).To(Equal(1))

		svc := rtest.GetResource(resources, "calico-api", "calico-system", "", "v1", "Service").(*corev1.Service)
		Expect(len(svc.Spec.Ports)).To(Equal(1))
		Expect(svc.Spec.Ports[0].Name).To(Equal(render.APIServerPortName))
		Expect(svc.Spec.Ports[0].Port).To(Equal(int32(443)))
		Expect(svc.Spec.Ports[0].TargetPort.IntValue()).To(Equal(5443))
	})

	It("should include a ControlPlaneNodeSelector when specified", func() {
		cfg.Installation.ControlPlaneNodeSelector = map[string]string{"nodeName": "control01"}
		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		d := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(d.Spec.Template.Spec.NodeSelector).To(HaveLen(1))
		Expect(d.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("nodeName", "control01"))
	})

	It("should include a ControlPlaneToleration when specified", func() {
		tol := corev1.Toleration{
			Key:      "foo",
			Operator: corev1.TolerationOpEqual,
			Value:    "bar",
			Effect:   corev1.TaintEffectNoExecute,
		}
		cfg.Installation.ControlPlaneTolerations = []corev1.Toleration{tol}
		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		resources, _ := component.Objects()
		d := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(d.Spec.Template.Spec.Tolerations).To(ContainElements(append(rmeta.TolerateControlPlane, tol)))
	})

	It("should set KUBERNETES_SERVICE_... variables if host networked", func() {
		cfg.K8SServiceEndpoint.Host = "k8shost"
		cfg.K8SServiceEndpoint.Port = "1234"
		cfg.Installation.KubernetesProvider = operatorv1.ProviderDockerEE
		cfg.ForceHostNetwork = true

		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		deploymentResource := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment")
		Expect(deploymentResource).ToNot(BeNil())

		deployment := deploymentResource.(*appsv1.Deployment)
		rtest.ExpectK8sServiceEpEnvVars(deployment.Spec.Template.Spec, "k8shost", "1234")
	})

	It("should set RecreateDeploymentStrategyType if host networked", func() {
		cfg.ForceHostNetwork = true
		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		resources, _ := component.Objects()
		d := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(d.Spec.Strategy.Type).To(Equal(appsv1.RecreateDeploymentStrategyType))
	})

	It("should not set KUBERNETES_SERVICE_... variables if Docker EE using proxy.local", func() {
		cfg.K8SServiceEndpoint.Host = "proxy.local"
		cfg.K8SServiceEndpoint.Port = "1234"
		cfg.Installation.KubernetesProvider = operatorv1.ProviderDockerEE

		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		deploymentResource := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment")
		Expect(deploymentResource).ToNot(BeNil())

		deployment := deploymentResource.(*appsv1.Deployment)
		rtest.ExpectNoK8sServiceEpEnvVars(deployment.Spec.Template.Spec)
	})

	It("should set KUBERNETES_SERVICE_... variables if Docker EE using non-proxy address", func() {
		cfg.K8SServiceEndpointPodNetwork.Host = "k8shost"
		cfg.K8SServiceEndpointPodNetwork.Port = "1234"
		cfg.Installation.KubernetesProvider = operatorv1.ProviderDockerEE

		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()

		deploymentResource := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment")
		Expect(deploymentResource).ToNot(BeNil())

		deployment := deploymentResource.(*appsv1.Deployment)
		rtest.ExpectK8sServiceEpEnvVars(deployment.Spec.Template.Spec, "k8shost", "1234")
	})

	It("should not render PodAffinity when ControlPlaneReplicas is 1", func() {
		var replicas int32 = 1
		cfg.Installation.ControlPlaneReplicas = &replicas

		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		resources, _ := component.Objects()

		deploy, ok := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(ok).To(BeTrue())
		Expect(deploy.Spec.Template.Spec.Affinity).To(BeNil())
	})

	It("should render PodAffinity when ControlPlaneReplicas is greater than 1", func() {
		var replicas int32 = 2
		cfg.Installation.ControlPlaneReplicas = &replicas

		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		resources, _ := component.Objects()

		deploy, ok := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(ok).To(BeTrue())
		Expect(deploy.Spec.Template.Spec.Affinity).NotTo(BeNil())
		Expect(deploy.Spec.Template.Spec.Affinity).To(Equal(podaffinity.NewPodAntiAffinity("calico-apiserver", []string{"calico-system", "tigera-system", "calico-apiserver"})))
	})

	It("should render with EKS provider without CNI.Type", func() {
		cfg.Installation.KubernetesProvider = operatorv1.ProviderEKS

		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		Expect(component.ResolveImages(nil)).To(BeNil())
		_, _ = component.Objects()
	})

	It("should render host networked with TKG provider", func() {
		cfg.Installation.KubernetesProvider = operatorv1.ProviderTKG
		cfg.Installation.CNI = &operatorv1.CNISpec{
			Type: operatorv1.PluginCalico,
		}

		component, err := render.APIServer(cfg)
		Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
		resources, _ := component.Objects()

		deploy, ok := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(ok).To(BeTrue())
		Expect(deploy.Spec.Template.Spec.HostNetwork).To(BeTrue())
	})

	Context("With APIServer Deployment overrides", func() {
		rr1 := corev1.ResourceRequirements{
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

		rr2 := corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("250m"),
				corev1.ResourceMemory: resource.MustParse("64Mi"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("500m"),
				corev1.ResourceMemory: resource.MustParse("500Mi"),
			},
		}

		It("should handle APIServerDeployment overrides", func() {
			var minReadySeconds int32 = 20

			affinity := &corev1.Affinity{
				NodeAffinity: &corev1.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
						NodeSelectorTerms: []corev1.NodeSelectorTerm{{
							MatchExpressions: []corev1.NodeSelectorRequirement{{
								Key:      "custom-affinity-key",
								Operator: corev1.NodeSelectorOpExists,
							}},
						}},
					},
				},
			}
			toleration := corev1.Toleration{
				Key:      "foo",
				Operator: corev1.TolerationOpEqual,
				Value:    "bar",
			}

			apiServerPort := operatorv1.APIServerDeploymentContainerPort{
				Name:          render.APIServerPortName,
				ContainerPort: 1111,
			}

			priorityclassname := "priority"

			cfg.APIServer.APIServerDeployment = &operatorv1.APIServerDeployment{
				Metadata: &operatorv1.Metadata{
					Labels:      map[string]string{"top-level": "label1"},
					Annotations: map[string]string{"top-level": "annot1"},
				},
				Spec: &operatorv1.APIServerDeploymentSpec{
					MinReadySeconds: &minReadySeconds,
					Template: &operatorv1.APIServerDeploymentPodTemplateSpec{
						Metadata: &operatorv1.Metadata{
							Labels:      map[string]string{"template-level": "label2"},
							Annotations: map[string]string{"template-level": "annot2"},
						},
						Spec: &operatorv1.APIServerDeploymentPodSpec{
							Containers: []operatorv1.APIServerDeploymentContainer{
								{
									Name:      "calico-apiserver",
									Resources: &rr1,
									Ports:     []operatorv1.APIServerDeploymentContainerPort{apiServerPort},
								},
							},
							InitContainers: []operatorv1.APIServerDeploymentInitContainer{
								{
									Name:      "calico-apiserver-certs-key-cert-provisioner",
									Resources: &rr2,
								},
							},
							NodeSelector: map[string]string{
								"custom-node-selector": "value",
							},
							Affinity:          affinity,
							Tolerations:       []corev1.Toleration{toleration},
							PriorityClassName: priorityclassname,
						},
					},
				},
			}
			// Enable certificate management.
			cfg.Installation.CertificateManagement = &operatorv1.CertificateManagement{SignerName: "a.b/c", CACert: cfg.TLSKeyPair.GetCertificatePEM()}
			certificateManager, err := certificatemanager.Create(cli, cfg.Installation, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
			Expect(err).NotTo(HaveOccurred())

			// Create and add the TLS keypair so the initContainer is rendered.
			dnsNames := dns.GetServiceDNSNames(render.APIServerServiceName, render.APIServerNamespace, clusterDomain)
			kp, err := certificateManager.GetOrCreateKeyPair(cli, render.CalicoAPIServerTLSSecretName, common.OperatorNamespace(), dnsNames)
			Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
			cfg.TLSKeyPair = kp
			qskp, err := certificateManager.GetOrCreateKeyPair(cli, render.CalicoAPIServerTLSSecretName, common.OperatorNamespace(), dnsNames)
			Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
			cfg.QueryServerTLSKeyPairCertificateManagementOnly = qskp

			component, err := render.APIServer(cfg)
			Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
			resources, _ := component.Objects()

			d, ok := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(ok).To(BeTrue())

			// API server has apiserver: true label
			Expect(d.Labels).To(HaveLen(2))
			Expect(d.Labels["apiserver"]).To(Equal("true"))
			Expect(d.Labels["top-level"]).To(Equal("label1"))
			Expect(d.Annotations).To(HaveLen(1))
			Expect(d.Annotations["top-level"]).To(Equal("annot1"))

			Expect(d.Spec.MinReadySeconds).To(Equal(minReadySeconds))

			// At runtime, the operator will also add some standard labels to the
			// deployment such as "k8s-app=calico-apiserver". But the APIServer
			// deployment object produced by the render will have no labels so we expect just the one
			// provided.
			Expect(d.Spec.Template.Labels).To(HaveLen(2))
			Expect(d.Spec.Template.Labels["apiserver"]).To(Equal("true"))
			Expect(d.Spec.Template.Labels["template-level"]).To(Equal("label2"))

			// With the default instance we expect 2 template-level annotations
			// - 1 added by the operator by default
			// - 1 added by the calicoNodeDaemonSet override
			Expect(d.Spec.Template.Annotations).To(HaveLen(2))
			Expect(d.Spec.Template.Annotations).To(HaveKey("tigera-operator.hash.operator.tigera.io/calico-apiserver-certs"))
			Expect(d.Spec.Template.Annotations["template-level"]).To(Equal("annot2"))

			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
			Expect(d.Spec.Template.Spec.Containers[0].Name).To(Equal("calico-apiserver"))
			Expect(d.Spec.Template.Spec.Containers[0].Resources).To(Equal(rr1))
			Expect(d.Spec.Template.Spec.Containers[0].Ports[0].Name).To(Equal(apiServerPort.Name))
			Expect(d.Spec.Template.Spec.Containers[0].Ports[0].ContainerPort).To(Equal(apiServerPort.ContainerPort))
			Expect(d.Spec.Template.Spec.Containers[0].Args[0]).To(ContainSubstring(fmt.Sprintf("--secure-port=%d", apiServerPort.ContainerPort)))

			Expect(d.Spec.Template.Spec.InitContainers).To(HaveLen(2))
			Expect(d.Spec.Template.Spec.InitContainers[0].Name).To(Equal("calico-apiserver-certs-key-cert-provisioner"))
			Expect(d.Spec.Template.Spec.InitContainers[0].Resources).To(Equal(rr2))

			Expect(d.Spec.Template.Spec.NodeSelector).To(HaveLen(1))
			Expect(d.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("custom-node-selector", "value"))

			Expect(d.Spec.Template.Spec.Tolerations).To(HaveLen(1))
			Expect(d.Spec.Template.Spec.Tolerations[0]).To(Equal(toleration))
			Expect(d.Spec.Template.Spec.PriorityClassName).To(Equal(priorityclassname))

			svc := rtest.GetResource(resources, "calico-api", "calico-system", "", "v1", "Service").(*corev1.Service)
			Expect(svc).NotTo(BeNil())
			Expect(svc.Spec.Ports).To(HaveLen(1))
			Expect(svc.Spec.Ports[0].Name).To(Equal(render.APIServerPortName))
			Expect(svc.Spec.Ports[0].Port).To(Equal(int32(443)))
			Expect(svc.Spec.Ports[0].TargetPort.IntVal).To(Equal(apiServerPort.ContainerPort))

			Expect(ok).To(BeTrue())
		})

		It("should override a ControlPlaneNodeSelector when specified", func() {
			cfg.Installation.ControlPlaneNodeSelector = map[string]string{"nodeName": "control01"}

			cfg.APIServer.APIServerDeployment = &operatorv1.APIServerDeployment{
				Spec: &operatorv1.APIServerDeploymentSpec{
					Template: &operatorv1.APIServerDeploymentPodTemplateSpec{
						Spec: &operatorv1.APIServerDeploymentPodSpec{
							NodeSelector: map[string]string{
								"custom-node-selector": "value",
							},
						},
					},
				},
			}
			component, err := render.APIServer(cfg)
			Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()
			d := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
			// nodeSelectors are merged
			Expect(d.Spec.Template.Spec.NodeSelector).To(HaveLen(2))
			Expect(d.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("nodeName", "control01"))
			Expect(d.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("custom-node-selector", "value"))
		})

		It("should override ControlPlaneTolerations when specified", func() {
			cfg.Installation.ControlPlaneTolerations = rmeta.TolerateControlPlane

			tol := corev1.Toleration{
				Key:      "foo",
				Operator: corev1.TolerationOpEqual,
				Value:    "bar",
				Effect:   corev1.TaintEffectNoExecute,
			}

			cfg.APIServer.APIServerDeployment = &operatorv1.APIServerDeployment{
				Spec: &operatorv1.APIServerDeploymentSpec{
					Template: &operatorv1.APIServerDeploymentPodTemplateSpec{
						Spec: &operatorv1.APIServerDeploymentPodSpec{
							Tolerations: []corev1.Toleration{tol},
						},
					},
				},
			}
			component, err := render.APIServer(cfg)
			Expect(err).To(BeNil(), "Expected APIServer to create successfully %s", err)
			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()
			d := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(d.Spec.Template.Spec.Tolerations).To(HaveLen(1))
			Expect(d.Spec.Template.Spec.Tolerations).To(ConsistOf(tol))
		})

		It("should render toleration on GKE", func() {
			cfg.Installation.KubernetesProvider = operatorv1.ProviderGKE

			component, err := render.APIServer(cfg)
			Expect(err).NotTo(HaveOccurred(), "Expected APIServer to create successfully %s", err)
			Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
			resources, _ := component.Objects()
			d := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(d).NotTo(BeNil())
			Expect(d.Spec.Template.Spec.Tolerations).To(ContainElement(corev1.Toleration{
				Key:      "kubernetes.io/arch",
				Operator: corev1.TolerationOpEqual,
				Value:    "arm64",
				Effect:   corev1.TaintEffectNoSchedule,
			}))
		})

		It("should render the correct env and/or images when FIPS mode is enabled (OSS)", func() {
			fipsEnabled := operatorv1.FIPSModeEnabled
			cfg.Installation.FIPSMode = &fipsEnabled

			component, err := render.APIServer(cfg)
			Expect(err).NotTo(HaveOccurred())

			Expect(component.ResolveImages(nil)).To(BeNil())
			resources, _ := component.Objects()

			d := rtest.GetResource(resources, "calico-apiserver", "calico-system", "apps", "v1", "Deployment").(*appsv1.Deployment)
			Expect(d.Spec.Template.Spec.Containers[0].Image).To(ContainSubstring("-fips"))
		})
	})

	Context("multi-tenant", func() {
		BeforeEach(func() {
			cfg.MultiTenant = true
			cfg.ManagementCluster = &operatorv1.ManagementCluster{Spec: operatorv1.ManagementClusterSpec{Address: "example.com:1234"}}
			cfg.Installation = &operatorv1.InstallationSpec{
				ControlPlaneReplicas: ptr.To[int32](2),
				Registry:             "testregistry.com/",
				Variant:              operatorv1.TigeraSecureEnterprise,
			}
		})

		It("should not install tigera-network-admin and tigera-ui-user", func() {
			component, err := render.APIServer(cfg)
			Expect(err).NotTo(HaveOccurred())

			// Expect no UISettings / UISettingsGroups to be installed.
			resources, _ := component.Objects()
			obj := rtest.GetResource(resources, "tigera-network-admin", "", "rbac.authorization.k8s.io", "v1", "ClusterRole")
			Expect(obj).To(BeNil())
			obj = rtest.GetResource(resources, "tigera-ui-user", "", "rbac.authorization.k8s.io", "v1", "ClusterRole")
			Expect(obj).To(BeNil())
		})

		It("should create a cluster role that get managed clusters", func() {
			component, err := render.APIServer(cfg)
			Expect(err).NotTo(HaveOccurred())

			resources, _ := component.Objects()
			managedClusterAccessRole := rtest.GetResource(resources,
				render.MultiTenantManagedClustersAccessClusterRoleName, "", rbacv1.GroupName, "v1", "ClusterRole").(*rbacv1.ClusterRole)
			expectedManagedClusterAccessRules := []rbacv1.PolicyRule{
				{
					APIGroups: []string{"projectcalico.org"},
					Resources: []string{"managedclusters"},
					Verbs:     []string{"get"},
				},
			}
			Expect(managedClusterAccessRole.Rules).To(ContainElements(expectedManagedClusterAccessRules))
		})

		It("should create a cluster role for watching managed clusters", func() {
			component, err := render.APIServer(cfg)
			Expect(err).NotTo(HaveOccurred())

			resources, _ := component.Objects()
			managedClusterAccessRole := rtest.GetResource(resources,
				render.ManagedClustersWatchClusterRoleName, "", rbacv1.GroupName, "v1", "ClusterRole").(*rbacv1.ClusterRole)
			expectedManagedClusterAccessRules := []rbacv1.PolicyRule{
				{
					APIGroups: []string{"projectcalico.org"},
					Resources: []string{"managedclusters"},
					Verbs:     []string{"get", "list", "watch"},
				},
			}
			Expect(managedClusterAccessRole.Rules).To(ContainElements(expectedManagedClusterAccessRules))
		})

		It("should bind the calico-apiserver ClusterRole only to the calico-system service account", func() {
			component, err := render.APIServer(cfg)
			Expect(err).NotTo(HaveOccurred())

			resources, _ := component.Objects()
			crb := rtest.GetResource(resources,
				render.APIServerName, "", rbacv1.GroupName, "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
			Expect(crb.RoleRef.Name).To(Equal(render.APIServerName))
			// The aggregated API server always runs in calico-system, even in multi-tenant mode - its
			// full-privilege ClusterRole must not be bound to tenant service accounts.
			Expect(crb.Subjects).To(ConsistOf(rbacv1.Subject{
				Kind:      "ServiceAccount",
				Name:      render.APIServerServiceAccountName,
				Namespace: render.APIServerNamespace,
			}))
		})

		It("should grant each tenant's calico-apiserver service account least-privilege Linseed access", func() {
			cfg.BindingNamespaces = []string{"tenant-a", "tenant-b"}
			component, err := render.APIServer(cfg)
			Expect(err).NotTo(HaveOccurred())

			resources, _ := component.Objects()

			// A dedicated, Linseed-only ClusterRole.
			role := rtest.GetResource(resources,
				render.APIServerLinseedAccessClusterRoleName, "", rbacv1.GroupName, "v1", "ClusterRole").(*rbacv1.ClusterRole)
			Expect(role.Rules).To(ConsistOf(rbacv1.PolicyRule{
				APIGroups: []string{"linseed.tigera.io"},
				Resources: []string{"policyactivity"},
				Verbs:     []string{"get"},
			}))

			// A single ClusterRoleBinding with one calico-apiserver ServiceAccount subject per tenant namespace.
			// Linseed authorizes with a cluster-scoped SubjectAccessReview, so this must be a ClusterRoleBinding.
			crb := rtest.GetResource(resources,
				render.APIServerLinseedAccessClusterRoleName, "", rbacv1.GroupName, "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
			Expect(crb.RoleRef.Name).To(Equal(render.APIServerLinseedAccessClusterRoleName))
			Expect(crb.Subjects).To(ConsistOf(
				rbacv1.Subject{Kind: "ServiceAccount", Name: render.APIServerServiceAccountName, Namespace: "tenant-a"},
				rbacv1.Subject{Kind: "ServiceAccount", Name: render.APIServerServiceAccountName, Namespace: "tenant-b"},
			))
		})
	})
})
