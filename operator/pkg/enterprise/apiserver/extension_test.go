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

package apiserver_test

import (
	"context"
	"fmt"
	"reflect"
	"slices"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	admregv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/apis"
	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/controller"
	"github.com/projectcalico/calico/operator/pkg/controller/certificatemanager"
	"github.com/projectcalico/calico/operator/pkg/controller/k8sapi"
	"github.com/projectcalico/calico/operator/pkg/controller/utils"
	ctrlrfake "github.com/projectcalico/calico/operator/pkg/ctrlruntime/client/fake"
	"github.com/projectcalico/calico/operator/pkg/dns"
	"github.com/projectcalico/calico/operator/pkg/enterprise"
	eoptions "github.com/projectcalico/calico/operator/pkg/enterprise/options"
	"github.com/projectcalico/calico/operator/pkg/enterprise/render/monitor"
	"github.com/projectcalico/calico/operator/pkg/extensions"
	"github.com/projectcalico/calico/operator/pkg/extensions/extensionstest"
	"github.com/projectcalico/calico/operator/pkg/render"
	"github.com/projectcalico/calico/operator/pkg/render/common/networkpolicy"
	"github.com/projectcalico/calico/operator/pkg/render/common/rbacmanagement"
	"github.com/projectcalico/calico/operator/pkg/render/webhooks"
	"github.com/projectcalico/calico/operator/pkg/tls/certificatemanagement"
)

const apiServerClusterDomain = "cluster.local"

// apiServerControllerInputs builds a controller inputs for the API server controller,
// seeded with a fake client that holds objs. The returned context carries a real
// certificate manager and trusted bundle, so ExtendInputs can create the query server
// cert and the bundle the modifiers consume.
func apiServerControllerInputs(variant operatorv1.ProductVariant, install *operatorv1.InstallationSpec, objs ...client.Object) controller.Inputs {
	return apiServerControllerInputsWith(ctrlrfake.DefaultFakeClientBuilder(apiServerScheme()).Build(), variant, install, objs...)
}

// apiServerControllerInputsWith is apiServerControllerInputs against a caller-supplied client.
func apiServerControllerInputsWith(c client.WithWatch, variant operatorv1.ProductVariant, install *operatorv1.InstallationSpec, objs ...client.Object) controller.Inputs {
	for _, o := range objs {
		Expect(c.Create(context.Background(), o)).NotTo(HaveOccurred())
	}

	if install == nil {
		install = &operatorv1.InstallationSpec{Variant: variant}
	}

	certManager, err := certificatemanager.Create(c, install, apiServerClusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
	Expect(err).NotTo(HaveOccurred())

	return controller.Inputs{
		RenderInputs: render.Inputs{
			Installation:  install,
			ClusterDomain: apiServerClusterDomain,
			TrustedBundle: certManager.CreateTrustedBundle(),
		},
		Client:             c,
		CertificateManager: certManager,
	}
}

func apiServerScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
	return scheme
}

// failingConfigMapInputs returns controller inputs whose client fails every read of
// the named ConfigMap with readErr.
func failingConfigMapInputs(name string, readErr error) controller.Inputs {
	return failingGetInputs(failingGet{obj: &corev1.ConfigMap{}, name: name}, readErr)
}

// failingGet names the object read that should fail: any object of the same type as
// obj, narrowed to a single name when one is given.
type failingGet struct {
	obj  client.Object
	name string
}

func (f failingGet) matches(key client.ObjectKey, obj client.Object) bool {
	if reflect.TypeOf(obj) != reflect.TypeOf(f.obj) {
		return false
	}
	return f.name == "" || f.name == key.Name
}

// failingGetInputs returns controller inputs whose client fails the read fail
// describes with readErr.
func failingGetInputs(fail failingGet, readErr error, objs ...client.Object) controller.Inputs {
	c := ctrlrfake.DefaultFakeClientBuilder(apiServerScheme()).WithInterceptorFuncs(interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if fail.matches(key, obj) {
				return readErr
			}
			return c.Get(ctx, key, obj, opts...)
		},
	}).Build()
	return apiServerControllerInputsWith(c, operatorv1.CalicoEnterprise, nil, objs...)
}

// rbacManagementGate builds the admin-owned ConfigMap that switches the RBAC
// management UI on for a cluster.
func rbacManagementGate(enabled string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: rbacmanagement.ConfigMapName, Namespace: common.CalicoNamespace},
		Data:       map[string]string{rbacmanagement.ConfigMapKey: enabled},
	}
}

// apiServerKeyPair issues the API server TLS keypair from the inputs' certificate
// manager, the way the controller does before rendering.
func apiServerKeyPair(ci controller.Inputs) certificatemanagement.KeyPairInterface {
	dnsNames := dns.GetServiceDNSNames(render.APIServerServiceName, render.APIServerNamespace, ci.RenderInputs.ClusterDomain)
	kp, err := ci.CertificateManager.GetOrCreateKeyPair(ci.Client, render.CalicoAPIServerTLSSecretName, common.OperatorNamespace(), dnsNames)
	Expect(err).NotTo(HaveOccurred())
	return kp
}

var _ = Describe("API server enterprise controller extension", func() {
	managementCluster := func() *operatorv1.ManagementCluster {
		return &operatorv1.ManagementCluster{
			ObjectMeta: metav1.ObjectMeta{Name: utils.DefaultEnterpriseInstanceKey.Name},
			Spec: operatorv1.ManagementClusterSpec{
				Address: "example.com:1234",
				TLS:     &operatorv1.TLS{SecretName: render.VoltronTunnelSecretName},
			},
		}
	}

	tunnelSecret := func() *corev1.Secret {
		return &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: render.VoltronTunnelSecretName, Namespace: common.OperatorNamespace()},
			Data:       map[string][]byte{"cert": []byte("a"), "key": []byte("b")},
		}
	}

	managementClusterConnection := func() *operatorv1.ManagementClusterConnection {
		return &operatorv1.ManagementClusterConnection{
			ObjectMeta: metav1.ObjectMeta{Name: utils.DefaultEnterpriseInstanceKey.Name},
		}
	}

	Describe("configuration", func() {
		extendInputs := func(objs ...client.Object) error {
			ci := apiServerControllerInputs(operatorv1.CalicoEnterprise, nil, objs...)
			_, _, err := ext.APIServer().ExtendInputs(ctx, ci)
			return err
		}

		It("accepts a cluster with neither a ManagementCluster nor a ManagementClusterConnection", func() {
			Expect(extendInputs()).NotTo(HaveOccurred())
		})

		It("accepts a management cluster", func() {
			Expect(extendInputs(managementCluster(), tunnelSecret())).NotTo(HaveOccurred())
		})

		It("accepts a managed cluster", func() {
			Expect(extendInputs(managementClusterConnection())).NotTo(HaveOccurred())
		})

		It("rejects a cluster that is both a management cluster and a managed cluster", func() {
			err := extendInputs(managementCluster(), tunnelSecret(), managementClusterConnection())
			reason, ok := extensions.DegradedReason(err)
			Expect(ok).To(BeTrue())
			Expect(reason).To(Equal(operatorv1.ResourceValidationError))
		})
	})

	DescribeTable("reports the degraded reason for the read it failed on",
		func(fail failingGet, expected operatorv1.TigeraStatusReason, objs ...client.Object) {
			readErr := fmt.Errorf("the API server is having a bad day")

			_, _, err := ext.APIServer().ExtendInputs(ctx, failingGetInputs(fail, readErr, objs...))
			Expect(err).To(MatchError(readErr))
			reason, ok := extensions.DegradedReason(err)
			Expect(ok).To(BeTrue())
			Expect(reason).To(Equal(expected))
		},
		Entry("the ApplicationLayer",
			failingGet{obj: &operatorv1.ApplicationLayer{}}, operatorv1.ResourceReadError),
		Entry("the ManagementCluster",
			failingGet{obj: &operatorv1.ManagementCluster{}}, operatorv1.ResourceReadError),
		Entry("the ManagementClusterConnection",
			failingGet{obj: &operatorv1.ManagementClusterConnection{}}, operatorv1.ResourceReadError),
		Entry("the tunnel secret on a management cluster",
			failingGet{obj: &corev1.Secret{}, name: render.VoltronTunnelSecretName}, operatorv1.ResourceReadError,
			managementCluster()),
		Entry("the prometheus client certificate",
			failingGet{obj: &corev1.Secret{}, name: monitor.PrometheusClientTLSSecretName}, operatorv1.ResourceReadError),
		Entry("the Voltron linseed certificate on a managed cluster",
			failingGet{obj: &corev1.Secret{}, name: render.VoltronLinseedPublicCert}, operatorv1.ResourceReadError,
			managementClusterConnection()),
		Entry("the Authentication",
			failingGet{obj: &operatorv1.Authentication{}}, operatorv1.ResourceReadError),
	)

	Describe("Dex", func() {
		readyAuthentication := func() *operatorv1.Authentication {
			return &operatorv1.Authentication{
				ObjectMeta: metav1.ObjectMeta{Name: utils.DefaultEnterpriseInstanceKey.Name},
				Status:     operatorv1.AuthenticationStatus{State: operatorv1.TigeraStatusReady},
			}
		}

		It("reports not ready while the Dex TLS secret is missing", func() {
			// WithObjects, since Create drops the status the extension keys off.
			c := ctrlrfake.DefaultFakeClientBuilder(apiServerScheme()).WithObjects(readyAuthentication()).Build()
			ci := apiServerControllerInputsWith(c, operatorv1.CalicoEnterprise, nil)

			_, _, err := ext.APIServer().ExtendInputs(ctx, ci)
			reason, ok := extensions.DegradedReason(err)
			Expect(ok).To(BeTrue())
			Expect(reason).To(Equal(operatorv1.ResourceNotReady))
			Expect(err.Error()).To(ContainSubstring(render.DexTLSSecretName))
		})
	})
})

var _ = Describe("API server enterprise modifier", func() {
	// renderAPIServerWith builds the base API server objects and runs the extension
	// over them, returning the create and delete lists it produced.
	renderAPIServerWith := func(s extensions.Extensions, ci controller.Inputs, ri render.Inputs, kp certificatemanagement.KeyPairInterface) ([]client.Object, []client.Object) {
		cfg := &render.APIServerConfiguration{
			RequiresAggregationServer: true,
			K8SServiceEndpoint:        k8sapi.ServiceEndpoint{},
			Installation:              ci.RenderInputs.Installation,
			APIServer:                 &operatorv1.APIServerSpec{},
			TLSKeyPair:                kp,
			TrustedBundle:             ri.TrustedBundle,
			KubernetesVersion:         &common.VersionInfo{Major: 1, Minor: 31},
		}
		comp, err := render.APIServer(cfg)
		Expect(err).NotTo(HaveOccurred())
		Expect(comp.ResolveImages(nil)).NotTo(HaveOccurred())
		create, del := comp.Objects()

		return s.APIServer().Modify(extensionstest.APIServerStub{StubComponent: extensionstest.StubComponent{Create: create, Delete: del}, Cfg: cfg}, ri).Objects()
	}

	renderAPIServer := func(ci controller.Inputs, ri render.Inputs, kp certificatemanagement.KeyPairInterface) ([]client.Object, []client.Object) {
		return renderAPIServerWith(ext, ci, ri, kp)
	}

	apiServerDeployment := func(objs []client.Object) *appsv1.Deployment {
		dp, ok := extensions.FindObject[*appsv1.Deployment](objs, render.APIServerName)
		Expect(ok).To(BeTrue())
		return dp
	}

	container := func(dp *appsv1.Deployment, name string) *corev1.Container {
		for i := range dp.Spec.Template.Spec.Containers {
			if dp.Spec.Template.Spec.Containers[i].Name == name {
				return &dp.Spec.Template.Spec.Containers[i]
			}
		}
		return nil
	}

	It("adds no enterprise objects when the operator runs as Calico", func() {
		ci := apiServerControllerInputs(operatorv1.Calico, nil)
		eci, _, err := calicoExt.APIServer().ExtendInputs(ctx, ci)
		ri := eci.RenderInputs
		Expect(err).NotTo(HaveOccurred())

		objs, _ := renderAPIServerWith(calicoExt, ci, ri, apiServerKeyPair(ci))

		// Only the cleanup is registered as Calico, and it only queues deletes.
		_, ok := extensions.FindObject[*rbacv1.ClusterRole](objs, "tigera-ui-user")
		Expect(ok).To(BeFalse())
		dp := apiServerDeployment(objs)
		Expect(container(dp, render.TigeraAPIServerQueryServerContainerName)).To(BeNil())
	})

	It("layers the query server, enterprise RBAC, audit policy, and query server port on", func() {
		ci := apiServerControllerInputs(operatorv1.CalicoEnterprise, nil)
		eci, _, err := ext.APIServer().ExtendInputs(ctx, ci)
		ri := eci.RenderInputs
		Expect(err).NotTo(HaveOccurred())

		objs, _ := renderAPIServer(ci, ri, apiServerKeyPair(ci))

		// The query server container is layered onto the deployment.
		dp := apiServerDeployment(objs)
		Expect(container(dp, render.TigeraAPIServerQueryServerContainerName)).NotTo(BeNil())

		// Enterprise RBAC.
		for _, name := range []string{"calico-apiserver", "tigera-ui-user", "tigera-network-admin", "calico-uisettingsgroup-getter", "calico-uisettings-passthrough"} {
			_, ok := extensions.FindObject[*rbacv1.ClusterRole](objs, name)
			Expect(ok).To(BeTrue(), "expected ClusterRole %q", name)
		}

		// The user and network-admin roles grant access to WAF policy resources.
		uiUser, found := extensions.FindObject[*rbacv1.ClusterRole](objs, "tigera-ui-user")
		Expect(found).To(BeTrue())
		Expect(uiUser.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups: []string{"applicationlayer.projectcalico.org"},
			Resources: []string{
				"globalwafpolicies",
				"globalwafplugins",
				"globalwafvalidationpolicies",
				"wafpolicies",
				"wafplugins",
				"wafvalidationpolicies",
			},
			Verbs: []string{"get", "watch", "list"},
		}))

		networkAdmin, found := extensions.FindObject[*rbacv1.ClusterRole](objs, "tigera-network-admin")
		Expect(found).To(BeTrue())
		Expect(networkAdmin.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups: []string{"applicationlayer.projectcalico.org"},
			Resources: []string{
				"globalwafpolicies",
				"globalwafplugins",
				"globalwafvalidationpolicies",
				"wafpolicies",
				"wafplugins",
				"wafvalidationpolicies",
			},
			Verbs: []string{"create", "update", "delete", "patch", "get", "watch", "list"},
		}))

		// Both roles can read Gateways and HTTPRoutes to offer as WAF policy attach targets.
		for _, role := range []*rbacv1.ClusterRole{uiUser, networkAdmin} {
			Expect(role.Rules).To(ContainElement(rbacv1.PolicyRule{
				APIGroups: []string{"gateway.networking.k8s.io"},
				Resources: []string{"gateways", "httproutes"},
				Verbs:     []string{"get", "list", "watch"},
			}))
		}

		Expect(uiUser.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups: []string{"operator.tigera.io"},
			Resources: []string{"gatewayapis"},
			Verbs:     []string{"get"},
		}))
		Expect(networkAdmin.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups: []string{"operator.tigera.io"},
			Resources: []string{"gatewayapis"},
			Verbs:     []string{"get", "create", "update", "patch"},
		}))

		// Audit policy configmap.
		_, ok := extensions.FindObject[*corev1.ConfigMap](objs, "calico-audit-policy")
		Expect(ok).To(BeTrue())

		// The query server port is added to the Service.
		svc, ok := extensions.FindObject[*corev1.Service](objs, render.APIServerServiceName)
		Expect(ok).To(BeTrue())
		Expect(svc.Spec.Ports).To(ContainElement(HaveField("Name", render.QueryServerPortName)))
	})

	DescribeTable("grants tigera-network-admin the role management verbs only when RBAC management is enabled",
		func(gate *corev1.ConfigMap, expected bool) {
			var objs []client.Object
			if gate != nil {
				objs = append(objs, gate)
			}
			ci := apiServerControllerInputs(operatorv1.CalicoEnterprise, nil, objs...)
			eci, _, err := ext.APIServer().ExtendInputs(ctx, ci)
			Expect(err).NotTo(HaveOccurred())

			rendered, _ := renderAPIServer(ci, eci.RenderInputs, apiServerKeyPair(ci))
			networkAdmin, ok := extensions.FindObject[*rbacv1.ClusterRole](rendered, "tigera-network-admin")
			Expect(ok).To(BeTrue())

			// ui-apis writes bindings impersonating the caller, so the caller's own role
			// has to carry the verbs or the apiserver's escalation check rejects it.
			matcher := ContainElement(rbacv1.PolicyRule{
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"clusterrolebindings", "rolebindings"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "delete"},
			})
			if expected {
				Expect(networkAdmin.Rules).To(matcher)
			} else {
				Expect(networkAdmin.Rules).NotTo(matcher)
			}
		},
		Entry("enabled", rbacManagementGate("true"), true),
		Entry("disabled", rbacManagementGate("false"), false),
		Entry("no ConfigMap", nil, false),
	)

	It("reads the gate on a managed cluster, which carries tigera-network-admin too", func() {
		ci := apiServerControllerInputs(operatorv1.CalicoEnterprise, nil,
			&operatorv1.ManagementClusterConnection{ObjectMeta: metav1.ObjectMeta{Name: utils.DefaultEnterpriseInstanceKey.Name}},
			rbacManagementGate("true"))
		eci, _, err := ext.APIServer().ExtendInputs(ctx, ci)
		Expect(err).NotTo(HaveOccurred())

		objs, _ := renderAPIServer(ci, eci.RenderInputs, apiServerKeyPair(ci))
		networkAdmin, ok := extensions.FindObject[*rbacv1.ClusterRole](objs, "tigera-network-admin")
		Expect(ok).To(BeTrue())
		Expect(networkAdmin.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups: []string{"rbac.authorization.k8s.io"},
			Resources: []string{"clusterrolebindings", "rolebindings"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "delete"},
		}))
	})

	It("fails the reconcile when the gate ConfigMap cannot be read", func() {
		// Unknown state is not the same as absent, so it must not render as disabled.
		readErr := fmt.Errorf("the API server is having a bad day")
		ci := failingConfigMapInputs(rbacmanagement.ConfigMapName, readErr)

		_, _, err := ext.APIServer().ExtendInputs(ctx, ci)
		Expect(err).To(MatchError(readErr))
		reason, ok := extensions.DegradedReason(err)
		Expect(ok).To(BeTrue())
		Expect(reason).To(Equal(operatorv1.ResourceReadError))
	})

	Context("Calico Cloud", func() {
		cloudExt := func() extensions.Extensions {
			return enterprise.New(operatorv1.CalicoEnterprise, eoptions.Options{Cloud: true})
		}

		uiSettingsRules := func(role *rbacv1.ClusterRole) []rbacv1.PolicyRule {
			var rules []rbacv1.PolicyRule
			for _, r := range role.Rules {
				if slices.Contains(r.Resources, "uisettingsgroups") || slices.Contains(r.Resources, "uisettingsgroups/data") {
					rules = append(rules, r)
				}
			}
			return rules
		}

		lmaResourceNames := func(role *rbacv1.ClusterRole) []string {
			for _, r := range role.Rules {
				if slices.Contains(r.APIGroups, "lma.tigera.io") {
					return r.ResourceNames
				}
			}
			return nil
		}

		objectsFor := func(s extensions.Extensions) ([]client.Object, []client.Object) {
			ci := apiServerControllerInputs(operatorv1.CalicoEnterprise, nil)
			eci, _, err := s.APIServer().ExtendInputs(ctx, ci)
			Expect(err).NotTo(HaveOccurred())
			return renderAPIServerWith(s, ci, eci.RenderInputs, apiServerKeyPair(ci))
		}

		It("exposes only the user-settings UISettings group", func() {
			objs, _ := objectsFor(cloudExt())

			uiUser, ok := extensions.FindObject[*rbacv1.ClusterRole](objs, "tigera-ui-user")
			Expect(ok).To(BeTrue())
			Expect(uiSettingsRules(uiUser)).To(ConsistOf(
				rbacv1.PolicyRule{
					APIGroups:     []string{"projectcalico.org"},
					Resources:     []string{"uisettingsgroups"},
					Verbs:         []string{"get"},
					ResourceNames: []string{"user-settings"},
				},
				rbacv1.PolicyRule{
					APIGroups:     []string{"projectcalico.org"},
					Resources:     []string{"uisettingsgroups/data"},
					Verbs:         []string{"*"},
					ResourceNames: []string{"user-settings"},
				},
			))

			networkAdmin, ok := extensions.FindObject[*rbacv1.ClusterRole](objs, "tigera-network-admin")
			Expect(ok).To(BeTrue())
			Expect(uiSettingsRules(networkAdmin)).To(ConsistOf(
				rbacv1.PolicyRule{
					APIGroups:     []string{"projectcalico.org"},
					Resources:     []string{"uisettingsgroups"},
					Verbs:         []string{"get"},
					ResourceNames: []string{"user-settings"},
				},
				rbacv1.PolicyRule{
					APIGroups:     []string{"projectcalico.org"},
					Resources:     []string{"uisettingsgroups/data"},
					Verbs:         []string{"*"},
					ResourceNames: []string{"user-settings"},
				},
			))
		})

		It("grants access to runtime logs", func() {
			objs, _ := objectsFor(cloudExt())

			uiUser, ok := extensions.FindObject[*rbacv1.ClusterRole](objs, "tigera-ui-user")
			Expect(ok).To(BeTrue())
			Expect(lmaResourceNames(uiUser)).To(ContainElement("runtime"))

			networkAdmin, ok := extensions.FindObject[*rbacv1.ClusterRole](objs, "tigera-network-admin")
			Expect(ok).To(BeTrue())
			Expect(lmaResourceNames(networkAdmin)).To(ContainElement("runtime"))
		})

		It("leaves the cluster-settings group and omits runtime logs off cloud", func() {
			objs, _ := objectsFor(ext)

			uiUser, ok := extensions.FindObject[*rbacv1.ClusterRole](objs, "tigera-ui-user")
			Expect(ok).To(BeTrue())
			Expect(uiSettingsRules(uiUser)).To(ContainElement(rbacv1.PolicyRule{
				APIGroups:     []string{"projectcalico.org"},
				Resources:     []string{"uisettingsgroups"},
				Verbs:         []string{"get"},
				ResourceNames: []string{"cluster-settings", "user-settings"},
			}))
			Expect(lmaResourceNames(uiUser)).NotTo(ContainElement("runtime"))

			networkAdmin, ok := extensions.FindObject[*rbacv1.ClusterRole](objs, "tigera-network-admin")
			Expect(ok).To(BeTrue())
			Expect(uiSettingsRules(networkAdmin)).To(ContainElement(rbacv1.PolicyRule{
				APIGroups:     []string{"projectcalico.org"},
				Resources:     []string{"uisettingsgroups"},
				Verbs:         []string{"get", "patch", "update"},
				ResourceNames: []string{"cluster-settings", "user-settings"},
			}))
			Expect(lmaResourceNames(networkAdmin)).NotTo(ContainElement("runtime"))
		})
	})

	It("queues the enterprise RBAC for deletion when not a management cluster", func() {
		ci := apiServerControllerInputs(operatorv1.CalicoEnterprise, nil)
		eci, _, err := ext.APIServer().ExtendInputs(ctx, ci)
		ri := eci.RenderInputs
		Expect(err).NotTo(HaveOccurred())

		_, del := renderAPIServer(ci, ri, apiServerKeyPair(ci))
		_, ok := extensions.FindObject[*rbacv1.ClusterRole](del, render.ManagedClustersWatchClusterRoleName)
		Expect(ok).To(BeTrue())
	})

	Context("management cluster", func() {
		It("adds the tunnel args and the managed-cluster-watch and secrets RBAC", func() {
			ci := apiServerControllerInputs(operatorv1.CalicoEnterprise, nil,
				&operatorv1.ManagementCluster{
					ObjectMeta: metav1.ObjectMeta{Name: utils.DefaultEnterpriseInstanceKey.Name},
					Spec: operatorv1.ManagementClusterSpec{
						Address: "example.com:1234",
						TLS:     &operatorv1.TLS{SecretName: render.VoltronTunnelSecretName},
					},
				},
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: render.VoltronTunnelSecretName, Namespace: common.OperatorNamespace()},
					Data:       map[string][]byte{"cert": []byte("a"), "key": []byte("b")},
				},
			)
			eci, _, err := ext.APIServer().ExtendInputs(ctx, ci)
			ri := eci.RenderInputs
			Expect(err).NotTo(HaveOccurred())

			objs, _ := renderAPIServer(ci, ri, apiServerKeyPair(ci))

			dp := apiServerDeployment(objs)
			apiCtr := container(dp, render.APIServerContainerName)
			Expect(apiCtr).NotTo(BeNil())
			Expect(apiCtr.Args).To(ContainElement("--enable-managed-clusters-create-api=true"))
			Expect(apiCtr.Args).To(ContainElement("--managementClusterAddr=example.com:1234"))
			Expect(apiCtr.Args).To(ContainElement("--tunnelSecretName=" + render.VoltronTunnelSecretName))

			_, ok := extensions.FindObject[*rbacv1.ClusterRole](objs, render.ManagedClustersWatchClusterRoleName)
			Expect(ok).To(BeTrue())
			_, ok = extensions.FindObject[*rbacv1.Role](objs, render.APIServerSecretsRBACName)
			Expect(ok).To(BeTrue())
		})
	})

	Context("managed cluster", func() {
		It("adds the external Linseed rolebinding and the query server token volume", func() {
			ci := apiServerControllerInputs(operatorv1.CalicoEnterprise, nil,
				&operatorv1.ManagementClusterConnection{
					ObjectMeta: metav1.ObjectMeta{Name: utils.DefaultEnterpriseInstanceKey.Name},
				},
			)
			eci, _, err := ext.APIServer().ExtendInputs(ctx, ci)
			ri := eci.RenderInputs
			Expect(err).NotTo(HaveOccurred())

			objs, _ := renderAPIServer(ci, ri, apiServerKeyPair(ci))

			_, ok := extensions.FindObject[*rbacv1.RoleBinding](objs, "tigera-linseed")
			Expect(ok).To(BeTrue())

			dp := apiServerDeployment(objs)
			Expect(dp.Spec.Template.Spec.Volumes).To(ContainElement(HaveField("Name", render.LinseedTokenVolumeName)))
			qs := container(dp, render.TigeraAPIServerQueryServerContainerName)
			Expect(qs).NotTo(BeNil())
			Expect(qs.Env).To(ContainElement(HaveField("Name", "LINSEED_TOKEN")))
		})
	})

	Context("multi-tenant management cluster", func() {
		// renderMultiTenantAPIServer mirrors renderAPIServer but sets MultiTenant on the render
		// config, so the modifier takes the multi-tenant RBAC branch.
		renderMultiTenantAPIServer := func(ci controller.Inputs, ri render.Inputs, kp certificatemanagement.KeyPairInterface) ([]client.Object, []client.Object) {
			cfg := &render.APIServerConfiguration{
				RequiresAggregationServer: true,
				K8SServiceEndpoint:        k8sapi.ServiceEndpoint{},
				Installation:              ci.RenderInputs.Installation,
				APIServer:                 &operatorv1.APIServerSpec{},
				TLSKeyPair:                kp,
				TrustedBundle:             ri.TrustedBundle,
				KubernetesVersion:         &common.VersionInfo{Major: 1, Minor: 31},
				MultiTenant:               true,
			}
			comp, err := render.APIServer(cfg)
			Expect(err).NotTo(HaveOccurred())
			Expect(comp.ResolveImages(nil)).NotTo(HaveOccurred())
			create, del := comp.Objects()

			return ext.APIServer().Modify(extensionstest.APIServerStub{StubComponent: extensionstest.StubComponent{Create: create, Delete: del}, Cfg: cfg}, ri).Objects()
		}

		tenant := func(namespace string) *operatorv1.Tenant {
			return &operatorv1.Tenant{
				ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: namespace},
				Spec:       operatorv1.TenantSpec{ID: namespace},
			}
		}

		multiTenantExt := func() extensions.Extensions {
			return enterprise.New(operatorv1.CalicoEnterprise, eoptions.Options{MultiTenant: true})
		}

		It("does not render tigera-network-admin, so the RBAC management gate needs no tenancy term", func() {
			ci := apiServerControllerInputs(operatorv1.CalicoEnterprise, nil, rbacManagementGate("true"))
			eci, _, err := multiTenantExt().APIServer().ExtendInputs(ctx, ci)
			Expect(err).NotTo(HaveOccurred())

			objs, _ := renderMultiTenantAPIServer(ci, eci.RenderInputs, apiServerKeyPair(ci))
			_, ok := extensions.FindObject[*rbacv1.ClusterRole](objs, "tigera-network-admin")
			Expect(ok).To(BeFalse())
		})

		It("grants each tenant's calico-apiserver service account least-privilege Linseed access", func() {
			ci := apiServerControllerInputs(operatorv1.CalicoEnterprise, nil, tenant("tenant-a"), tenant("tenant-b"))
			eci, _, err := multiTenantExt().APIServer().ExtendInputs(ctx, ci)
			ri := eci.RenderInputs
			Expect(err).NotTo(HaveOccurred())

			objs, _ := renderMultiTenantAPIServer(ci, ri, apiServerKeyPair(ci))

			// A dedicated, Linseed-only ClusterRole.
			role, ok := extensions.FindObject[*rbacv1.ClusterRole](objs, "calico-apiserver-linseed-access")
			Expect(ok).To(BeTrue())
			Expect(role.Rules).To(ConsistOf(rbacv1.PolicyRule{
				APIGroups: []string{"linseed.tigera.io"},
				Resources: []string{"policyactivity"},
				Verbs:     []string{"get"},
			}))

			// A single ClusterRoleBinding with one calico-apiserver ServiceAccount subject per tenant
			// namespace. Linseed authorizes with a cluster-scoped SubjectAccessReview, so this must be a
			// ClusterRoleBinding.
			crb, ok := extensions.FindObject[*rbacv1.ClusterRoleBinding](objs, "calico-apiserver-linseed-access")
			Expect(ok).To(BeTrue())
			Expect(crb.RoleRef.Name).To(Equal("calico-apiserver-linseed-access"))
			Expect(crb.Subjects).To(ConsistOf(
				rbacv1.Subject{Kind: "ServiceAccount", Name: render.APIServerServiceAccountName, Namespace: "tenant-a"},
				rbacv1.Subject{Kind: "ServiceAccount", Name: render.APIServerServiceAccountName, Namespace: "tenant-b"},
			))

			// The zero-tenant user/network-admin roles are not installed in multi-tenant mode.
			_, ok = extensions.FindObject[*rbacv1.ClusterRole](objs, "tigera-ui-user")
			Expect(ok).To(BeFalse())
		})

		It("queues the Linseed-access RBAC for deletion in zero-tenant mode", func() {
			ci := apiServerControllerInputs(operatorv1.CalicoEnterprise, nil)
			eci, _, err := ext.APIServer().ExtendInputs(ctx, ci)
			ri := eci.RenderInputs
			Expect(err).NotTo(HaveOccurred())

			_, del := renderAPIServer(ci, ri, apiServerKeyPair(ci))
			_, ok := extensions.FindObject[*rbacv1.ClusterRole](del, "calico-apiserver-linseed-access")
			Expect(ok).To(BeTrue())
			_, ok = extensions.FindObject[*rbacv1.ClusterRoleBinding](del, "calico-apiserver-linseed-access")
			Expect(ok).To(BeTrue())
		})
	})

	Context("v3-CRD mode (no aggregation server)", func() {
		It("renders the deployment skeleton with the query server and pulls it out of the delete list", func() {
			ci := apiServerControllerInputs(operatorv1.CalicoEnterprise, nil)
			eci, _, err := ext.APIServer().ExtendInputs(ctx, ci)
			ri := eci.RenderInputs
			Expect(err).NotTo(HaveOccurred())

			cfg := &render.APIServerConfiguration{
				RequiresAggregationServer: false,
				K8SServiceEndpoint:        k8sapi.ServiceEndpoint{},
				Installation:              ci.RenderInputs.Installation,
				APIServer:                 &operatorv1.APIServerSpec{},
				TLSKeyPair:                apiServerKeyPair(ci),
				TrustedBundle:             ri.TrustedBundle,
				KubernetesVersion:         &common.VersionInfo{Major: 1, Minor: 31},
			}
			comp, err := render.APIServer(cfg)
			Expect(err).NotTo(HaveOccurred())
			Expect(comp.ResolveImages(nil)).NotTo(HaveOccurred())
			create, del := comp.Objects()

			// The base queues the deployment objects for deletion in v3-CRD mode.
			_, ok := extensions.FindObject[*appsv1.Deployment](del, render.APIServerName)
			Expect(ok).To(BeTrue())

			create, del = ext.APIServer().Modify(extensionstest.APIServerStub{StubComponent: extensionstest.StubComponent{Create: create, Delete: del}, Cfg: cfg}, ri).Objects()

			// After the modifier, the deployment (with the query server container) is in the
			// create list and out of the delete list.
			dp, ok := extensions.FindObject[*appsv1.Deployment](create, render.APIServerName)
			Expect(ok).To(BeTrue())
			Expect(container(dp, render.TigeraAPIServerQueryServerContainerName)).NotTo(BeNil())
			_, ok = extensions.FindObject[*appsv1.Deployment](del, render.APIServerName)
			Expect(ok).To(BeFalse())
		})

		It("registers no APIService", func() {
			ci := apiServerControllerInputs(operatorv1.CalicoEnterprise, nil)
			eci, _, err := ext.APIServer().ExtendInputs(ctx, ci)
			ri := eci.RenderInputs
			Expect(err).NotTo(HaveOccurred())

			cfg := &render.APIServerConfiguration{
				RequiresAggregationServer: false,
				K8SServiceEndpoint:        k8sapi.ServiceEndpoint{},
				Installation:              ci.RenderInputs.Installation,
				APIServer:                 &operatorv1.APIServerSpec{},
				TLSKeyPair:                apiServerKeyPair(ci),
				TrustedBundle:             ri.TrustedBundle,
				KubernetesVersion:         &common.VersionInfo{Major: 1, Minor: 31},
			}
			comp, err := render.APIServer(cfg)
			Expect(err).NotTo(HaveOccurred())
			Expect(comp.ResolveImages(nil)).NotTo(HaveOccurred())
			create, del := comp.Objects()

			create, _ = ext.APIServer().Modify(extensionstest.APIServerStub{StubComponent: extensionstest.StubComponent{Create: create, Delete: del}, Cfg: cfg}, ri).Objects()

			for _, r := range create {
				Expect(r.GetObjectKind().GroupVersionKind().Kind).NotTo(Equal("APIService"),
					"unexpected APIService registered in v3 CRD mode: %s", r.GetName())
			}
		})
	})

	Context("sidecar / L7 injection", func() {
		applicationLayerSidecar := func() *operatorv1.ApplicationLayer {
			enabled := operatorv1.SidecarEnabled
			return &operatorv1.ApplicationLayer{
				ObjectMeta: metav1.ObjectMeta{Name: utils.DefaultEnterpriseInstanceKey.Name},
				Spec:       operatorv1.ApplicationLayerSpec{SidecarInjection: &enabled},
			}
		}

		It("adds the L7 admission controller container, the sidecar webhook, and the L7 service port", func() {
			ci := apiServerControllerInputs(operatorv1.CalicoEnterprise, nil, applicationLayerSidecar())
			eci, _, err := ext.APIServer().ExtendInputs(ctx, ci)
			ri := eci.RenderInputs
			Expect(err).NotTo(HaveOccurred())

			objs, _ := renderAPIServer(ci, ri, apiServerKeyPair(ci))

			dp := apiServerDeployment(objs)
			Expect(container(dp, render.L7AdmissionControllerContainerName)).NotTo(BeNil())

			_, ok := extensions.FindObject[*admregv1.MutatingWebhookConfiguration](objs, common.SidecarMutatingWebhookConfigName)
			Expect(ok).To(BeTrue())

			svc, ok := extensions.FindObject[*corev1.Service](objs, render.APIServerServiceName)
			Expect(ok).To(BeTrue())
			Expect(svc.Spec.Ports).To(ContainElement(HaveField("Name", render.L7AdmissionControllerPortName)))
		})

		It("pulls the sidecar webhook out of the delete list", func() {
			ci := apiServerControllerInputs(operatorv1.CalicoEnterprise, nil, applicationLayerSidecar())
			eci, _, err := ext.APIServer().ExtendInputs(ctx, ci)
			ri := eci.RenderInputs
			Expect(err).NotTo(HaveOccurred())

			_, del := renderAPIServer(ci, ri, apiServerKeyPair(ci))
			_, ok := extensions.FindObject[*admregv1.MutatingWebhookConfiguration](del, common.SidecarMutatingWebhookConfigName)
			Expect(ok).To(BeFalse())
		})
	})
})

var _ = Describe("API server enterprise policy modifier", func() {
	applyPolicy := func(ci controller.Inputs, ri render.Inputs) *v3.NetworkPolicy {
		cfg := &render.APIServerConfiguration{
			RequiresAggregationServer: true,
			K8SServiceEndpoint:        k8sapi.ServiceEndpoint{},
			Installation:              ci.RenderInputs.Installation,
			APIServer:                 &operatorv1.APIServerSpec{},
		}
		comp := render.APIServerPolicy(cfg)
		create, del := comp.Objects()
		objs, _ := ext.APIServer().Modify(extensionstest.APIServerPolicyStub{StubComponent: extensionstest.StubComponent{Create: create, Delete: del}, Cfg: cfg}, ri).Objects()
		policy, ok := extensions.FindObject[*v3.NetworkPolicy](objs, render.APIServerPolicyName)
		Expect(ok).To(BeTrue())
		return policy
	}

	It("leaves the egress rules as the base when no OIDC key validator is configured", func() {
		ci := apiServerControllerInputs(operatorv1.CalicoEnterprise, nil)
		eci, _, err := ext.APIServer().ExtendInputs(ctx, ci)
		ri := eci.RenderInputs
		Expect(err).NotTo(HaveOccurred())

		policy := applyPolicy(ci, ri)
		// The trailing rule remains the Pass rule (no OIDC egress rule inserted).
		n := len(policy.Spec.Egress)
		Expect(n).To(BeNumerically(">", 0))
		Expect(policy.Spec.Egress[n-1].Action).To(Equal(v3.Pass))
	})

	It("allows egress to Guardian on a managed cluster", func() {
		ci := apiServerControllerInputs(operatorv1.CalicoEnterprise, nil,
			&operatorv1.ManagementClusterConnection{ObjectMeta: metav1.ObjectMeta{Name: utils.DefaultEnterpriseInstanceKey.Name}})
		eci, _, err := ext.APIServer().ExtendInputs(ctx, ci)
		ri := eci.RenderInputs
		Expect(err).NotTo(HaveOccurred())

		policy := applyPolicy(ci, ri)
		guardian := v3.Rule{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: render.GuardianEntityRule,
		}
		// The rule is only reached if it precedes the trailing Pass.
		n := len(policy.Spec.Egress)
		Expect(policy.Spec.Egress[n-1].Action).To(Equal(v3.Pass))
		Expect(policy.Spec.Egress[n-2]).To(Equal(guardian))
	})

	It("omits the Guardian egress rule when the cluster is not managed", func() {
		ci := apiServerControllerInputs(operatorv1.CalicoEnterprise, nil)
		eci, _, err := ext.APIServer().ExtendInputs(ctx, ci)
		ri := eci.RenderInputs
		Expect(err).NotTo(HaveOccurred())

		policy := applyPolicy(ci, ri)
		Expect(policy.Spec.Egress).NotTo(ContainElement(HaveField("Destination", render.GuardianEntityRule)))
	})

	It("adds the L7 admission controller ingress port when sidecar injection is enabled", func() {
		enabled := operatorv1.SidecarEnabled
		ci := apiServerControllerInputs(operatorv1.CalicoEnterprise, nil, &operatorv1.ApplicationLayer{
			ObjectMeta: metav1.ObjectMeta{Name: utils.DefaultEnterpriseInstanceKey.Name},
			Spec:       operatorv1.ApplicationLayerSpec{SidecarInjection: &enabled},
		})
		eci, _, err := ext.APIServer().ExtendInputs(ctx, ci)
		ri := eci.RenderInputs
		Expect(err).NotTo(HaveOccurred())

		policy := applyPolicy(ci, ri)
		// Every ingress rule should carry the L7 admission controller port.
		found := false
		for _, rule := range policy.Spec.Ingress {
			for _, p := range rule.Destination.Ports {
				if p.MinPort == uint16(render.L7AdmissionControllerPort) {
					found = true
				}
			}
		}
		Expect(found).To(BeTrue(), "expected the L7 admission controller ingress port")
	})
})

var _ = Describe("webhooks enterprise modifier", func() {
	// renderWebhooksWith builds the base webhooks objects and runs the extension over them,
	// returning the create and delete lists it produced.
	renderWebhooksWith := func(s extensions.Extensions, ci controller.Inputs, ri render.Inputs, kp certificatemanagement.KeyPairInterface) ([]client.Object, []client.Object) {
		cfg := &webhooks.Configuration{
			KeyPair:      kp,
			Installation: ci.RenderInputs.Installation,
			APIServer:    &operatorv1.APIServerSpec{},
		}
		comp := webhooks.Component(cfg)
		Expect(comp.ResolveImages(nil)).NotTo(HaveOccurred())
		create, del := comp.Objects()

		return s.APIServer().Modify(extensionstest.WebhooksStub{StubComponent: extensionstest.StubComponent{Create: create, Delete: del}, Cfg: cfg}, ri).Objects()
	}

	renderWebhooks := func(objs ...client.Object) ([]client.Object, []client.Object) {
		ci := apiServerControllerInputs(operatorv1.CalicoEnterprise, nil, objs...)
		eci, _, err := ext.APIServer().ExtendInputs(ctx, ci)
		Expect(err).NotTo(HaveOccurred())
		return renderWebhooksWith(ext, ci, eci.RenderInputs, apiServerKeyPair(ci))
	}

	webhooksArgs := func(objs []client.Object) []string {
		dp, ok := extensions.FindObject[*appsv1.Deployment](objs, webhooks.WebhooksName)
		Expect(ok).To(BeTrue())
		return dp.Spec.Template.Spec.Containers[0].Args
	}

	mutatingWebhooks := func(objs []client.Object) []admregv1.MutatingWebhook {
		mwc, ok := extensions.FindObject[*admregv1.MutatingWebhookConfiguration](objs, "api.projectcalico.org")
		Expect(ok).To(BeTrue())
		return mwc.Webhooks
	}

	managerTLSManagementCluster := func() *operatorv1.ManagementCluster {
		return &operatorv1.ManagementCluster{
			ObjectMeta: metav1.ObjectMeta{Name: utils.DefaultEnterpriseInstanceKey.Name},
			Spec: operatorv1.ManagementClusterSpec{
				Address: "mgmt.example.com:9449",
				TLS:     &operatorv1.TLS{SecretName: render.ManagerTLSSecretName},
			},
		}
	}

	managerTLSSecret := func() *corev1.Secret {
		return &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: render.ManagerTLSSecretName, Namespace: common.OperatorNamespace()},
			Data:       map[string][]byte{"cert": []byte("a"), "key": []byte("b")},
		}
	}

	It("registers the ManagedCluster webhook and the MCM flags on a management cluster", func() {
		mc := &operatorv1.ManagementCluster{
			ObjectMeta: metav1.ObjectMeta{Name: utils.DefaultEnterpriseInstanceKey.Name},
			Spec: operatorv1.ManagementClusterSpec{
				Address: "mgmt.example.com:9449",
				TLS:     &operatorv1.TLS{SecretName: render.VoltronTunnelSecretName},
			},
		}
		objs, _ := renderWebhooks(mc, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: render.VoltronTunnelSecretName, Namespace: common.OperatorNamespace()},
			Data:       map[string][]byte{"cert": []byte("a"), "key": []byte("b")},
		})

		hooks := mutatingWebhooks(objs)
		Expect(hooks).To(HaveLen(2))
		Expect(hooks[0].Name).To(Equal("uisettings.api.projectcalico.org"))
		Expect(hooks[1].Name).To(Equal("managedclusters.api.projectcalico.org"))
		Expect(*hooks[1].ClientConfig.Service.Path).To(Equal("/managedcluster"))
		Expect(*hooks[1].FailurePolicy).To(Equal(admregv1.Fail))
		Expect(hooks[1].Rules).To(HaveLen(1))
		Expect(hooks[1].Rules[0].Operations).To(ConsistOf(admregv1.Create))
		Expect(hooks[1].Rules[0].Rule.Resources).To(Equal([]string{"managedclusters"}))

		args := webhooksArgs(objs)
		Expect(args).To(ContainElement("--mcm-management-cluster-addr=mgmt.example.com:9449"))
		Expect(args).To(ContainElement(fmt.Sprintf("--mcm-tunnel-secret-name=%s", render.VoltronTunnelSecretName)))
		Expect(args).NotTo(ContainElement("--mcm-management-cluster-ca-type=Public"))
		Expect(args).NotTo(ContainElement("--multi-tenant=true"))
	})

	It("sets the Public CA type when the tunnel secret is the manager TLS secret", func() {
		objs, _ := renderWebhooks(managerTLSManagementCluster(), managerTLSSecret())
		Expect(webhooksArgs(objs)).To(ContainElement("--mcm-management-cluster-ca-type=Public"))
	})

	It("passes the multi-tenant flag on a multi-tenant management cluster", func() {
		mtExt := enterprise.New(operatorv1.CalicoEnterprise, eoptions.Options{MultiTenant: true})
		ci := apiServerControllerInputs(operatorv1.CalicoEnterprise, nil, managerTLSManagementCluster(), managerTLSSecret())
		eci, _, err := mtExt.APIServer().ExtendInputs(ctx, ci)
		Expect(err).NotTo(HaveOccurred())

		objs, _ := renderWebhooksWith(mtExt, ci, eci.RenderInputs, apiServerKeyPair(ci))
		Expect(webhooksArgs(objs)).To(ContainElement("--multi-tenant=true"))
	})

	It("renders the tunnel secret RBAC namespaced for a single-tenant management cluster", func() {
		objs, _ := renderWebhooks(managerTLSManagementCluster(), managerTLSSecret())

		role, ok := extensions.FindObject[*rbacv1.Role](objs, webhooks.WebhooksSecretsRBACName)
		Expect(ok).To(BeTrue())
		Expect(role.Rules).To(ConsistOf(rbacv1.PolicyRule{
			APIGroups:     []string{""},
			Resources:     []string{"secrets"},
			Verbs:         []string{"get"},
			ResourceNames: []string{render.ManagerTLSSecretName},
		}))

		rb, ok := extensions.FindObject[*rbacv1.RoleBinding](objs, webhooks.WebhooksSecretsRBACName)
		Expect(ok).To(BeTrue())
		Expect(rb.Subjects).To(ConsistOf(rbacv1.Subject{
			Kind:      "ServiceAccount",
			Name:      webhooks.WebhooksName,
			Namespace: common.CalicoNamespace,
		}))
	})

	It("renders the tunnel secret RBAC cluster-scoped for a multi-tenant management cluster", func() {
		mtExt := enterprise.New(operatorv1.CalicoEnterprise, eoptions.Options{MultiTenant: true})
		ci := apiServerControllerInputs(operatorv1.CalicoEnterprise, nil, managerTLSManagementCluster(), managerTLSSecret())
		eci, _, err := mtExt.APIServer().ExtendInputs(ctx, ci)
		Expect(err).NotTo(HaveOccurred())

		objs, _ := renderWebhooksWith(mtExt, ci, eci.RenderInputs, apiServerKeyPair(ci))

		cr, ok := extensions.FindObject[*rbacv1.ClusterRole](objs, webhooks.WebhooksSecretsRBACName)
		Expect(ok).To(BeTrue())
		Expect(cr.Rules).To(ConsistOf(rbacv1.PolicyRule{
			APIGroups:     []string{""},
			Resources:     []string{"secrets"},
			Verbs:         []string{"get"},
			ResourceNames: []string{render.ManagerTLSSecretName},
		}))

		crb, ok := extensions.FindObject[*rbacv1.ClusterRoleBinding](objs, webhooks.WebhooksSecretsRBACName)
		Expect(ok).To(BeTrue())
		Expect(crb.Subjects).To(ConsistOf(rbacv1.Subject{
			Kind:      "ServiceAccount",
			Name:      webhooks.WebhooksName,
			Namespace: common.CalicoNamespace,
		}))
	})

	It("queues the tunnel secret RBAC for deletion when not a management cluster", func() {
		create, del := renderWebhooks()

		Expect(mutatingWebhooks(create)).To(HaveLen(1))
		Expect(webhooksArgs(create)).NotTo(ContainElement(ContainSubstring("--mcm-")))
		for _, name := range []string{webhooks.WebhooksSecretsRBACName} {
			_, ok := extensions.FindObject[*rbacv1.ClusterRole](del, name)
			Expect(ok).To(BeTrue())
			_, ok = extensions.FindObject[*rbacv1.ClusterRoleBinding](del, name)
			Expect(ok).To(BeTrue())
			_, ok = extensions.FindObject[*rbacv1.Role](del, name)
			Expect(ok).To(BeTrue())
			_, ok = extensions.FindObject[*rbacv1.RoleBinding](del, name)
			Expect(ok).To(BeTrue())
		}
	})

	It("queues the tunnel secret RBAC for deletion when the operator runs as Calico", func() {
		ci := apiServerControllerInputs(operatorv1.Calico, nil)
		eci, _, err := calicoExt.APIServer().ExtendInputs(ctx, ci)
		Expect(err).NotTo(HaveOccurred())

		_, del := renderWebhooksWith(calicoExt, ci, eci.RenderInputs, apiServerKeyPair(ci))

		_, ok := extensions.FindObject[*rbacv1.ClusterRole](del, webhooks.WebhooksSecretsRBACName)
		Expect(ok).To(BeTrue())
	})

	It("runs the webhook container as root so it can write audit logs", func() {
		create, _ := renderWebhooks()

		dp, ok := extensions.FindObject[*appsv1.Deployment](create, webhooks.WebhooksName)
		Expect(ok).To(BeTrue())
		ctr := dp.Spec.Template.Spec.Containers[0]
		Expect(*ctr.SecurityContext.RunAsUser).To(Equal(int64(0)))
		Expect(*ctr.SecurityContext.RunAsNonRoot).To(BeFalse())
		Expect(*ctr.SecurityContext.Privileged).To(BeFalse())
	})

	It("marks the security context privileged on OpenShift", func() {
		ci := apiServerControllerInputs(operatorv1.CalicoEnterprise, nil)
		ci.RenderInputs.Installation.KubernetesProvider = operatorv1.ProviderOpenShift
		eci, _, err := ext.APIServer().ExtendInputs(ctx, ci)
		Expect(err).NotTo(HaveOccurred())

		create, _ := renderWebhooksWith(ext, ci, eci.RenderInputs, apiServerKeyPair(ci))

		dp, ok := extensions.FindObject[*appsv1.Deployment](create, webhooks.WebhooksName)
		Expect(ok).To(BeTrue())
		Expect(*dp.Spec.Template.Spec.Containers[0].SecurityContext.Privileged).To(BeTrue())
	})

	It("mounts the audit log directory off the host", func() {
		create, _ := renderWebhooks()

		dp, ok := extensions.FindObject[*appsv1.Deployment](create, webhooks.WebhooksName)
		Expect(ok).To(BeTrue())
		podSpec := dp.Spec.Template.Spec
		Expect(podSpec.Containers[0].VolumeMounts).To(ContainElement(corev1.VolumeMount{
			Name:      "audit-logs",
			MountPath: "/var/log/calico/audit",
		}))
		Expect(podSpec.Volumes).To(ContainElement(corev1.Volume{
			Name: "audit-logs",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/var/log/calico/audit",
					Type: ptr.To(corev1.HostPathDirectoryOrCreate),
				},
			},
		}))
	})

	It("registers the audit logging webhook against every v3 resource", func() {
		create, _ := renderWebhooks()

		vwc, ok := extensions.FindObject[*admregv1.ValidatingWebhookConfiguration](create, "api.projectcalico.org")
		Expect(ok).To(BeTrue())
		Expect(vwc.Webhooks).To(ContainElement(HaveField("Name", "audit-logging.api.projectcalico.org")))

		hook := vwc.Webhooks[len(vwc.Webhooks)-1]
		Expect(*hook.ClientConfig.Service.Path).To(Equal("/audit"))
		Expect(*hook.FailurePolicy).To(Equal(admregv1.Ignore))
		Expect(hook.Rules).To(HaveLen(1))
		Expect(hook.Rules[0].Rule.Resources).To(Equal([]string{"*"}))
		Expect(hook.Rules[0].Operations).To(ConsistOf(
			admregv1.Create, admregv1.Update, admregv1.Delete, admregv1.Connect,
		))
	})

	It("registers the UISettings mutating webhook", func() {
		create, _ := renderWebhooks()

		hooks := mutatingWebhooks(create)
		Expect(hooks).To(HaveLen(1))
		Expect(hooks[0].Name).To(Equal("uisettings.api.projectcalico.org"))
		Expect(*hooks[0].ClientConfig.Service.Path).To(Equal("/uisettings"))
		Expect(*hooks[0].FailurePolicy).To(Equal(admregv1.Fail))
		Expect(*hooks[0].TimeoutSeconds).To(Equal(int32(10)))
		Expect(hooks[0].Rules).To(HaveLen(1))
		Expect(hooks[0].Rules[0].Rule.Resources).To(Equal([]string{"uisettings"}))
	})

	It("grants the webhook the Enterprise-only permissions", func() {
		create, _ := renderWebhooks()

		cr, ok := extensions.FindObject[*rbacv1.ClusterRole](create, webhooks.WebhooksName)
		Expect(ok).To(BeTrue())
		Expect(cr.Rules).To(ContainElements(
			rbacv1.PolicyRule{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"managedclusters"},
				Verbs:     []string{"list", "watch", "update"},
			},
			rbacv1.PolicyRule{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"uisettingsgroups"},
				Verbs:     []string{"get"},
			},
		))
	})

	It("queues the mutating webhook configuration for deletion when the operator runs as Calico", func() {
		ci := apiServerControllerInputs(operatorv1.Calico, nil)
		eci, _, err := calicoExt.APIServer().ExtendInputs(ctx, ci)
		Expect(err).NotTo(HaveOccurred())

		create, del := renderWebhooksWith(calicoExt, ci, eci.RenderInputs, apiServerKeyPair(ci))

		_, ok := extensions.FindObject[*admregv1.MutatingWebhookConfiguration](del, "api.projectcalico.org")
		Expect(ok).To(BeTrue())
		_, ok = extensions.FindObject[*admregv1.MutatingWebhookConfiguration](create, "api.projectcalico.org")
		Expect(ok).To(BeFalse())
	})
})

// cleanupAPIServer behaviour for the Calico variant: the base render component carries
// the enterprise cleanup modifier, which queues the enterprise RBAC for deletion.
var _ = Describe("API server Calico-variant cleanup", func() {
	It("queues the enterprise RBAC for deletion", func() {
		ci := apiServerControllerInputs(operatorv1.Calico, nil)
		eci, _, err := calicoExt.APIServer().ExtendInputs(ctx, ci)
		ri := eci.RenderInputs
		Expect(err).NotTo(HaveOccurred())

		cfg := &render.APIServerConfiguration{
			RequiresAggregationServer: true,
			K8SServiceEndpoint:        k8sapi.ServiceEndpoint{},
			Installation:              ci.RenderInputs.Installation,
			APIServer:                 &operatorv1.APIServerSpec{},
			TLSKeyPair:                apiServerKeyPair(ci),
			KubernetesVersion:         &common.VersionInfo{Major: 1, Minor: 31},
		}
		comp, err := render.APIServer(cfg)
		Expect(err).NotTo(HaveOccurred())
		Expect(comp.ResolveImages(nil)).NotTo(HaveOccurred())
		create, del := comp.Objects()
		_, del = calicoExt.APIServer().Modify(extensionstest.APIServerStub{StubComponent: extensionstest.StubComponent{Create: create, Delete: del}, Cfg: cfg}, ri).Objects()

		_, ok := extensions.FindObject[*rbacv1.ClusterRole](del, "tigera-ui-user")
		Expect(ok).To(BeTrue())
		_, ok = extensions.FindObject[*rbacv1.ClusterRole](del, "calico-apiserver")
		Expect(ok).To(BeTrue())
	})
})
