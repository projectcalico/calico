// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package installation_test

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/utils"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/enterprise"
	"github.com/tigera/operator/pkg/enterprise/installation"
	eoptions "github.com/tigera/operator/pkg/enterprise/options"
	"github.com/tigera/operator/pkg/extensions"
	"github.com/tigera/operator/pkg/extensions/extensionstest"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/applicationlayer"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/rbacmanagement"
	"github.com/tigera/operator/pkg/render/kubecontrollers"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/tls"
)

var _ = Describe("kube-controllers enterprise modifier", func() {
	// kubeControllersDeployment is a minimal stand-in for the calico-kube-controllers
	// deployment the base render produces, so the modifier has something to mount onto.
	kubeControllersDeployment := func() *appsv1.Deployment {
		return &appsv1.Deployment{
			TypeMeta:   metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: kubecontrollers.KubeController, Namespace: common.CalicoNamespace},
			Spec: appsv1.DeploymentSpec{
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{Name: kubecontrollers.KubeController}},
					},
				},
			},
		}
	}

	It("mounts the metrics serving TLS keypair onto the deployment", func() {
		eci, _, err := ext.Installation().ExtendInputs(ctx, newControllerInputs(operatorv1.CalicoEnterprise))
		ri := eci.RenderInputs
		Expect(err).NotTo(HaveOccurred())

		objs, _ := ext.Installation().Modify(extensionstest.KubeControllersStub{StubComponent: extensionstest.StubComponent{Create: []client.Object{kubeControllersDeployment()}, Delete: nil}, Cfg: nil}, ri).Objects()
		dp, ok := extensions.FindObject[*appsv1.Deployment](objs, kubecontrollers.KubeController)
		Expect(ok).To(BeTrue())

		c := dp.Spec.Template.Spec.Containers[0]
		Expect(c.Env).To(ContainElements(
			corev1.EnvVar{Name: "TLS_KEY_PATH", Value: "/calico-kube-controllers-metrics-tls/tls.key"},
			corev1.EnvVar{Name: "TLS_CRT_PATH", Value: "/calico-kube-controllers-metrics-tls/tls.crt"},
			corev1.EnvVar{Name: "CLIENT_COMMON_NAME", Value: monitor.PrometheusClientTLSSecretName},
		))
		Expect(c.VolumeMounts).To(ContainElement(HaveField("Name", kubecontrollers.KubeControllerPrometheusTLSSecret)))
		Expect(dp.Spec.Template.Spec.Volumes).To(ContainElement(HaveField("Name", kubecontrollers.KubeControllerPrometheusTLSSecret)))
		Expect(dp.Spec.Template.Annotations).NotTo(BeEmpty(), "expected the cert hash annotation")
	})

	It("adds the cert-management init container when certificate management is enabled", func() {
		eci, _, err := ext.Installation().ExtendInputs(ctx, certManagementControllerInputs())
		ri := eci.RenderInputs
		Expect(err).NotTo(HaveOccurred())

		objs, _ := ext.Installation().Modify(extensionstest.KubeControllersStub{StubComponent: extensionstest.StubComponent{Create: []client.Object{kubeControllersDeployment()}, Delete: nil}, Cfg: nil}, ri).Objects()
		dp, ok := extensions.FindObject[*appsv1.Deployment](objs, kubecontrollers.KubeController)
		Expect(ok).To(BeTrue())

		Expect(dp.Spec.Template.Spec.InitContainers).To(HaveLen(1))
		Expect(dp.Spec.Template.Spec.InitContainers[0].Name).To(Equal(fmt.Sprintf("%s-key-cert-provisioner", kubecontrollers.KubeControllerPrometheusTLSSecret)))
	})
})

// certManagementControllerInputs builds a controller inputs whose certificate
// manager issues cert-management (CSR-based) keypairs.
func certManagementControllerInputs() controller.Inputs {
	scheme := runtime.NewScheme()
	Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
	c := ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

	ca, err := tls.MakeCA(rmeta.DefaultOperatorCASignerName())
	Expect(err).NotTo(HaveOccurred())
	caCert, _, err := ca.Config.GetPEMBytes()
	Expect(err).NotTo(HaveOccurred())

	installation := &operatorv1.InstallationSpec{
		Variant:               operatorv1.CalicoEnterprise,
		CertificateManagement: &operatorv1.CertificateManagement{CACert: caCert},
	}
	certManager, err := certificatemanager.Create(c, installation, "", common.OperatorNamespace(), certificatemanager.AllowCACreation())
	Expect(err).NotTo(HaveOccurred())

	return controller.Inputs{
		RenderInputs: render.Inputs{
			Installation:       installation,
			FelixConfiguration: &v3.FelixConfiguration{},
			TrustedBundle:      certManager.CreateTrustedBundle(),
			ClusterDomain:      "cluster.local",
		},
		Client:             c,
		CertificateManager: certManager,
	}
}

var _ = Describe("calico-kube-controllers enterprise surface", func() {
	calicoKubeControllersCfg := func(ci controller.Inputs) *kubecontrollers.KubeControllersConfiguration {
		return &kubecontrollers.KubeControllersConfiguration{
			Installation:      ci.RenderInputs.Installation,
			ClusterDomain:     ci.RenderInputs.ClusterDomain,
			TrustedBundle:     ci.RenderInputs.TrustedBundle,
			MetricsPort:       9094,
			Namespace:         common.CalicoNamespace,
			BindingNamespaces: []string{common.CalicoNamespace},
		}
	}

	// render builds the base calico-kube-controllers objects and applies the
	// enterprise modifier, exactly as the component handler does.
	renderKubeControllers := func(ci controller.Inputs, ri render.Inputs) []client.Object {
		comp := kubecontrollers.NewCalicoKubeControllers(calicoKubeControllersCfg(ci))
		Expect(comp.ResolveImages(nil)).NotTo(HaveOccurred())
		create, del := comp.Objects()
		out, _ := ext.Installation().Modify(extensionstest.KubeControllersStub{StubComponent: extensionstest.StubComponent{Create: create, Delete: del}, Cfg: nil}, ri).Objects()
		return out
	}

	kubeContainer := func(objs []client.Object) *corev1.Container {
		dp, ok := extensions.FindObject[*appsv1.Deployment](objs, kubecontrollers.KubeController)
		Expect(ok).To(BeTrue())
		return &dp.Spec.Template.Spec.Containers[0]
	}

	It("layers the enterprise rules, controllers, and metrics TLS on (WAF off)", func() {
		eci, _, err := ext.Installation().ExtendInputs(ctx, newControllerInputs(operatorv1.CalicoEnterprise))
		ri := eci.RenderInputs
		Expect(err).NotTo(HaveOccurred())
		objs := renderKubeControllers(newControllerInputs(operatorv1.CalicoEnterprise), ri)

		role, ok := extensions.FindObject[*rbacv1.ClusterRole](objs, kubecontrollers.KubeControllerRole)
		Expect(ok).To(BeTrue())
		Expect(role.Rules).To(ContainElement(HaveField("Resources", ContainElement("licensekeys"))))

		c := kubeContainer(objs)
		Expect(c.Env).To(ContainElement(corev1.EnvVar{
			Name: "ENABLED_CONTROLLERS", Value: "node,loadbalancer,service,federatedservices,usage",
		}))
		// Metrics serving TLS wired from the keypair the hook created.
		Expect(c.Env).To(ContainElement(HaveField("Name", "TLS_KEY_PATH")))
		// No GatewayAPI CR at all, so no WASM env, no WAF_GATEWAY_EXTENSION_ENABLED env,
		// and no webhook objects.
		Expect(c.Env).NotTo(ContainElement(HaveField("Name", "WASM_IMAGE")))
		Expect(c.Env).NotTo(ContainElement(HaveField("Name", "WAF_GATEWAY_EXTENSION_ENABLED")))
		_, ok = extensions.FindObject[*corev1.Service](objs, applicationlayer.WAFWebhookServiceName)
		Expect(ok).To(BeFalse())
	})

	It("grants the node controller's IPAM syncer list access to Networks", func() {
		eci, _, err := ext.Installation().ExtendInputs(ctx, newControllerInputs(operatorv1.CalicoEnterprise))
		Expect(err).NotTo(HaveOccurred())
		objs := renderKubeControllers(newControllerInputs(operatorv1.CalicoEnterprise), eci.RenderInputs)

		role, ok := extensions.FindObject[*rbacv1.ClusterRole](objs, kubecontrollers.KubeControllerRole)
		Expect(ok).To(BeTrue())
		Expect(role.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups: []string{"projectcalico.org", "crd.projectcalico.org"},
			Resources: []string{"networks"},
			Verbs:     []string{"watch", "list", "get"},
		}))
	})

	It("layers the full WAF surface on when the GatewayAPI extension is enabled", func() {
		ci := wafControllerInputs()
		eci, managed, err := ext.Installation().ExtendInputs(ctx, ci)
		ri := eci.RenderInputs
		Expect(err).NotTo(HaveOccurred())
		names := []string{}
		for _, kp := range managed {
			names = append(names, kp.GetName())
		}
		Expect(names).To(ContainElement(applicationlayer.WAFWebhookServerTLSSecretName))

		objs := renderKubeControllers(ci, ri)

		role, ok := extensions.FindObject[*rbacv1.ClusterRole](objs, kubecontrollers.KubeControllerRole)
		Expect(ok).To(BeTrue())
		Expect(role.Rules).To(ContainElement(HaveField("Resources", ContainElement("wafpolicies"))))

		c := kubeContainer(objs)
		Expect(c.Env).To(ContainElement(corev1.EnvVar{
			Name: "ENABLED_CONTROLLERS", Value: "node,loadbalancer,service,federatedservices,usage,applicationlayer",
		}))
		Expect(c.Env).To(ContainElement(corev1.EnvVar{
			Name: "WASM_IMAGE", Value: "test-reg/tigera/envoy-proxy:" + components.ComponentGatewayAPIEnvoyProxy.Version,
		}))
		Expect(c.Env).To(ContainElement(corev1.EnvVar{Name: "WASM_PULL_SECRET", Value: installation.WASMPullSecretName}))
		Expect(c.Env).To(ContainElement(corev1.EnvVar{Name: "WASM_CA_CERT", Value: installation.WASMCACertName}))
		Expect(c.Env).To(ContainElement(HaveField("Name", "WAF_WEBHOOK_CERT_DIR")))
		Expect(c.Env).To(ContainElement(corev1.EnvVar{Name: "WAF_GATEWAY_EXTENSION_ENABLED", Value: "true"}))
		Expect(c.Ports).To(ContainElement(corev1.ContainerPort{Name: "waf-webhook", ContainerPort: int32(9443), Protocol: corev1.ProtocolTCP}))

		// The webhook surface, the wasm pull secret, and the wasm CA bundle are rendered.
		_, ok = extensions.FindObject[*corev1.Service](objs, applicationlayer.WAFWebhookServiceName)
		Expect(ok).To(BeTrue())
		_, ok = extensions.FindObject[*corev1.Secret](objs, installation.WASMPullSecretName)
		Expect(ok).To(BeTrue())
		_, ok = extensions.FindObject[*corev1.ConfigMap](objs, installation.WASMCACertName)
		Expect(ok).To(BeTrue())
	})

	It("deletes the WAF webhook surface when the extension is disabled", func() {
		ci := newControllerInputs(operatorv1.CalicoEnterprise)
		eci, _, err := ext.Installation().ExtendInputs(ctx, ci)
		ri := eci.RenderInputs
		Expect(err).NotTo(HaveOccurred())

		comp := kubecontrollers.NewCalicoKubeControllers(calicoKubeControllersCfg(ci))
		Expect(comp.ResolveImages(nil)).NotTo(HaveOccurred())
		create, del := comp.Objects()
		_, toDelete := ext.Installation().Modify(extensionstest.KubeControllersStub{StubComponent: extensionstest.StubComponent{Create: create, Delete: del}, Cfg: nil}, ri).Objects()

		_, ok := extensions.FindObject[*corev1.Service](toDelete, applicationlayer.WAFWebhookServiceName)
		Expect(ok).To(BeTrue(), "the webhook Service should be queued for deletion")
	})

	It("keeps the WAF controller wired but de-programs when GatewayAPI is present and WAF is disabled", func() {
		ci := gatewayNoWAFControllerInputs()
		eci, _, err := ext.Installation().ExtendInputs(ctx, ci)
		ri := eci.RenderInputs
		Expect(err).NotTo(HaveOccurred())
		objs := renderKubeControllers(ci, ri)

		// The applicationlayer controller and its WAF v3 RBAC stay wired even though WAF
		// is disabled, so the controller can tear down the EnvoyExtensionPolicies it
		// generated instead of losing its RBAC in the same reconcile (EV-6751).
		role, ok := extensions.FindObject[*rbacv1.ClusterRole](objs, kubecontrollers.KubeControllerRole)
		Expect(ok).To(BeTrue())
		Expect(role.Rules).To(ContainElement(HaveField("Resources", ContainElement("wafpolicies"))))

		c := kubeContainer(objs)
		Expect(c.Env).To(ContainElement(corev1.EnvVar{
			Name: "ENABLED_CONTROLLERS", Value: "node,loadbalancer,service,federatedservices,usage,applicationlayer",
		}))
		// It is told to de-program rather than program via WAF_GATEWAY_EXTENSION_ENABLED=false.
		Expect(c.Env).To(ContainElement(corev1.EnvVar{Name: "WAF_GATEWAY_EXTENSION_ENABLED", Value: "false"}))

		// But none of the active surface: no WASM env, no webhook port, and the webhook
		// objects are not created.
		Expect(c.Env).NotTo(ContainElement(HaveField("Name", "WASM_IMAGE")))
		Expect(c.Ports).NotTo(ContainElement(HaveField("Name", "waf-webhook")))
		_, ok = extensions.FindObject[*corev1.Service](objs, applicationlayer.WAFWebhookServiceName)
		Expect(ok).To(BeFalse())
	})

	It("adds the WAF webhook ingress rule to the network policy when enabled", func() {
		ci := wafControllerInputs()
		eci, _, err := ext.Installation().ExtendInputs(ctx, ci)
		ri := eci.RenderInputs
		Expect(err).NotTo(HaveOccurred())

		comp := kubecontrollers.NewCalicoKubeControllersPolicy(calicoKubeControllersCfg(ci), nil)
		create, del := comp.Objects()
		objs, _ := ext.Installation().Modify(extensionstest.KubeControllersPolicyStub{StubComponent: extensionstest.StubComponent{Create: create, Delete: del}, Cfg: nil}, ri).Objects()

		policy, ok := extensions.FindObject[*v3.NetworkPolicy](objs, kubecontrollers.KubeControllerNetworkPolicyName)
		Expect(ok).To(BeTrue())
		Expect(policy.Spec.Ingress).To(ContainElement(v3.Rule{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				Ports: networkpolicy.Ports(uint16(applicationlayer.WAFWebhookContainerPort)),
			},
		}))
	})

	// The base policy has no manager egress rule; reaching the manager is enterprise-only.
	DescribeTable("adds the manager egress rule",
		func(objs []client.Object, expected v3.EntityRule) {
			ci := newControllerInputs(operatorv1.CalicoEnterprise, objs...)
			eci, _, err := ext.Installation().ExtendInputs(ctx, ci)
			Expect(err).NotTo(HaveOccurred())

			comp := kubecontrollers.NewCalicoKubeControllersPolicy(calicoKubeControllersCfg(ci), nil)
			create, del := comp.Objects()
			out, _ := ext.Installation().Modify(extensionstest.KubeControllersPolicyStub{StubComponent: extensionstest.StubComponent{Create: create, Delete: del}, Cfg: nil}, eci.RenderInputs).Objects()

			policy, ok := extensions.FindObject[*v3.NetworkPolicy](out, kubecontrollers.KubeControllerNetworkPolicyName)
			Expect(ok).To(BeTrue())
			Expect(policy.Spec.Egress).To(ContainElement(v3.Rule{
				Action:      v3.Allow,
				Protocol:    &networkpolicy.TCPProtocol,
				Destination: expected,
			}))
		},
		Entry("direct to the manager on a management or standalone cluster",
			nil, networkpolicy.DefaultHelper().ManagerEntityRule()),
		Entry("through Guardian on a managed cluster",
			[]client.Object{&operatorv1.ManagementClusterConnection{ObjectMeta: metav1.ObjectMeta{Name: utils.DefaultEnterpriseInstanceKey.Name}}},
			render.GuardianEntityRule),
	)

	Context("RBAC management gate", func() {
		gate := func(value string) client.Object {
			return &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: rbacmanagement.ConfigMapName, Namespace: common.CalicoNamespace},
				Data:       map[string]string{rbacmanagement.ConfigMapKey: value},
			}
		}

		// renderWith runs the extension end to end and returns the created and deleted objects.
		renderWith := func(s extensions.Extensions, objs ...client.Object) ([]client.Object, []client.Object) {
			ci := newControllerInputs(operatorv1.CalicoEnterprise, objs...)
			eci, _, err := s.Installation().ExtendInputs(ctx, ci)
			Expect(err).NotTo(HaveOccurred())

			comp := kubecontrollers.NewCalicoKubeControllers(calicoKubeControllersCfg(ci))
			Expect(comp.ResolveImages(nil)).NotTo(HaveOccurred())
			create, del := comp.Objects()
			return s.Installation().Modify(extensionstest.KubeControllersStub{StubComponent: extensionstest.StubComponent{Create: create, Delete: del}, Cfg: nil}, eci.RenderInputs).Objects()
		}

		enabledControllers := func(objs []client.Object) string {
			for _, env := range kubeContainer(objs).Env {
				if env.Name == "ENABLED_CONTROLLERS" {
					return env.Value
				}
			}
			Fail("no ENABLED_CONTROLLERS env on the kube-controllers container")
			return ""
		}

		It("reads a missing ConfigMap as disabled", func() {
			create, del := renderWith(ext)
			Expect(enabledControllers(create)).NotTo(ContainSubstring("rbacsync"))

			_, ok := extensions.FindObject[*rbacv1.Role](del, "calico-kube-controllers-rbac-sync")
			Expect(ok).To(BeTrue(), "the rbacsync Role should be queued for deletion")
		})

		It("follows the admin's value once they create the ConfigMap", func() {
			create, _ := renderWith(ext, gate("true"))
			Expect(enabledControllers(create)).To(ContainSubstring("rbacsync"))

			_, ok := extensions.FindObject[*rbacv1.Role](create, "calico-kube-controllers-rbac-sync")
			Expect(ok).To(BeTrue())
			_, ok = extensions.FindObject[*rbacv1.RoleBinding](create, "calico-kube-controllers-rbac-sync")
			Expect(ok).To(BeTrue())
		})

		It("switches the feature back off when the admin sets the value to false", func() {
			create, del := renderWith(ext, gate("false"))
			Expect(enabledControllers(create)).NotTo(ContainSubstring("rbacsync"))

			_, ok := extensions.FindObject[*rbacv1.Role](del, "calico-kube-controllers-rbac-sync")
			Expect(ok).To(BeTrue())
		})

		It("withholds rbacsync on a multi-tenant management cluster even with the gate on", func() {
			// Multi-tenant force-disables the feature on the ui-apis side.
			multiTenant := enterprise.New(operatorv1.CalicoEnterprise, eoptions.Options{MultiTenant: true})
			create, _ := renderWith(multiTenant, gate("true"))
			Expect(enabledControllers(create)).NotTo(ContainSubstring("rbacsync"))
		})

		It("never creates the ConfigMap itself", func() {
			create, _ := renderWith(ext, gate("true"))
			_, ok := extensions.FindObject[*corev1.ConfigMap](create, rbacmanagement.ConfigMapName)
			Expect(ok).To(BeFalse(), "the gate is admin-owned, so the operator must not render it")
		})
	})

	It("binds kube-controllers to the managed-cluster watch role only on a management cluster", func() {
		ci := newControllerInputs(operatorv1.CalicoEnterprise,
			&operatorv1.ManagementCluster{ObjectMeta: metav1.ObjectMeta{Name: utils.DefaultEnterpriseInstanceKey.Name}})
		eci, _, err := ext.Installation().ExtendInputs(ctx, ci)
		Expect(err).NotTo(HaveOccurred())

		comp := kubecontrollers.NewCalicoKubeControllers(calicoKubeControllersCfg(ci))
		Expect(comp.ResolveImages(nil)).NotTo(HaveOccurred())
		create, del := comp.Objects()
		out, _ := ext.Installation().Modify(extensionstest.KubeControllersStub{StubComponent: extensionstest.StubComponent{Create: create, Delete: del}, Cfg: nil}, eci.RenderInputs).Objects()
		_, ok := extensions.FindObject[*rbacv1.ClusterRoleBinding](out, kubecontrollers.ManagedClustersWatchRoleBindingName)
		Expect(ok).To(BeTrue())

		// No ManagementCluster, no binding.
		plain := newControllerInputs(operatorv1.CalicoEnterprise)
		eci, _, err = ext.Installation().ExtendInputs(ctx, plain)
		Expect(err).NotTo(HaveOccurred())
		comp = kubecontrollers.NewCalicoKubeControllers(calicoKubeControllersCfg(plain))
		Expect(comp.ResolveImages(nil)).NotTo(HaveOccurred())
		create, del = comp.Objects()
		out, _ = ext.Installation().Modify(extensionstest.KubeControllersStub{StubComponent: extensionstest.StubComponent{Create: create, Delete: del}, Cfg: nil}, eci.RenderInputs).Objects()
		_, ok = extensions.FindObject[*rbacv1.ClusterRoleBinding](out, kubecontrollers.ManagedClustersWatchRoleBindingName)
		Expect(ok).To(BeFalse())
	})
})

// wafControllerInputs builds a controller inputs with a WAF-enabled GatewayAPI CR
// and an install pull secret, so the installation hook produces the full WAF data.
func wafControllerInputs() controller.Inputs {
	scheme := runtime.NewScheme()
	Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
	c := ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

	Expect(c.Create(context.Background(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "pull", Namespace: common.OperatorNamespace()},
		Type:       corev1.SecretTypeDockerConfigJson,
		Data:       map[string][]byte{corev1.DockerConfigJsonKey: []byte(`{"auths":{"reg.example.com":{"auth":"abc"}}}`)},
	})).NotTo(HaveOccurred())

	enabled := operatorv1.WAFExtensionStateEnabled
	Expect(c.Create(context.Background(), &operatorv1.GatewayAPI{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec: operatorv1.GatewayAPISpec{
			Extensions: &operatorv1.GatewayAPIExtensions{WAF: &operatorv1.WAFExtensionSpec{State: &enabled}},
		},
	})).NotTo(HaveOccurred())

	certManager, err := certificatemanager.Create(c, nil, "", common.OperatorNamespace(), certificatemanager.AllowCACreation())
	Expect(err).NotTo(HaveOccurred())

	return controller.Inputs{
		RenderInputs: render.Inputs{
			Installation: &operatorv1.InstallationSpec{
				Variant:          operatorv1.CalicoEnterprise,
				Registry:         "test-reg/",
				ImagePullSecrets: []corev1.LocalObjectReference{{Name: "pull"}},
			},
			FelixConfiguration: &v3.FelixConfiguration{},
			TrustedBundle:      certManager.CreateTrustedBundle(),
			ClusterDomain:      "cluster.local",
		},
		Client:             c,
		CertificateManager: certManager,
	}
}

// gatewayNoWAFControllerInputs builds a controller inputs with a GatewayAPI CR
// present but its WAF extension explicitly disabled. The applicationlayer controller
// and its RBAC stay wired so it can de-program, but no active WAF surface is produced
// (EV-6751).
func gatewayNoWAFControllerInputs() controller.Inputs {
	scheme := runtime.NewScheme()
	Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
	c := ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

	Expect(c.Create(context.Background(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "pull", Namespace: common.OperatorNamespace()},
		Type:       corev1.SecretTypeDockerConfigJson,
		Data:       map[string][]byte{corev1.DockerConfigJsonKey: []byte(`{"auths":{"reg.example.com":{"auth":"abc"}}}`)},
	})).NotTo(HaveOccurred())

	disabled := operatorv1.WAFExtensionStateDisabled
	Expect(c.Create(context.Background(), &operatorv1.GatewayAPI{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec: operatorv1.GatewayAPISpec{
			Extensions: &operatorv1.GatewayAPIExtensions{WAF: &operatorv1.WAFExtensionSpec{State: &disabled}},
		},
	})).NotTo(HaveOccurred())

	certManager, err := certificatemanager.Create(c, nil, "", common.OperatorNamespace(), certificatemanager.AllowCACreation())
	Expect(err).NotTo(HaveOccurred())

	return controller.Inputs{
		RenderInputs: render.Inputs{
			Installation: &operatorv1.InstallationSpec{
				Variant:          operatorv1.CalicoEnterprise,
				Registry:         "test-reg/",
				ImagePullSecrets: []corev1.LocalObjectReference{{Name: "pull"}},
			},
			FelixConfiguration: &v3.FelixConfiguration{},
			TrustedBundle:      certManager.CreateTrustedBundle(),
			ClusterDomain:      "cluster.local",
		},
		Client:             c,
		CertificateManager: certManager,
	}
}
