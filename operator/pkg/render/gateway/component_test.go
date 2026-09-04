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

package gateway_test

import (
	"fmt"
	"reflect"

	envoyapi "github.com/envoyproxy/gateway/api/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gapi "sigs.k8s.io/gateway-api/apis/v1"
	gapiv1b1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/render/common/networkpolicy"
	"github.com/projectcalico/calico/operator/pkg/render/gateway"
	"github.com/projectcalico/calico/operator/pkg/tls/certificatemanagement"
)

var _ = Describe("Gateway component render", func() {
	const (
		gwNS       = "calico-system"
		bkNS       = "calico-system"
		hostname   = "manager.example.com"
		prefix     = "calico-manager"
		className  = "calico-gateway"
		svcName    = "calico-manager"
		svcPort    = int32(9443)
		caBundleCM = "tigera-ca-bundle"
		tlsName    = "calico-manager-gateway-tls"
	)

	var (
		cfg      *gateway.Configuration
		toCreate []client.Object
		toDelete []client.Object
	)

	BeforeEach(func() {
		secret, err := certificatemanagement.CreateSelfSignedSecret(tlsName, common.OperatorNamespace(), tlsName, nil)
		Expect(err).NotTo(HaveOccurred())
		kp := certificatemanagement.NewKeyPair(secret, []string{""}, "")

		cfg = &gateway.Configuration{
			Hostname:                     hostname,
			GatewayNamespace:             gwNS,
			GatewayClassName:             className,
			BackendServiceName:           svcName,
			BackendPort:                  svcPort,
			BackendNamespace:             bkNS,
			BackendCABundleConfigMapName: caBundleCM,
			TLSKeyPair:                   kp,
			ResourcePrefix:               prefix,
			ExtraProxyObjects:            proxyObjects(bkNS),
			OpenShift:                    false,
		}
	})

	Context("same namespace (gateway == backend)", func() {
		JustBeforeEach(func() {
			comp := gateway.Component(cfg)
			toCreate, toDelete = comp.Objects()
		})

		It("deletes the now-unneeded cross-namespace ReferenceGrant", func() {
			// With the gateway in the backend namespace the ReferenceGrant is
			// not rendered; the render deletes any stale one here, where it
			// holds the backend grant.
			Expect(findObject[*gapiv1b1.ReferenceGrant](toDelete, prefix+"-allow-gateway", bkNS)).NotTo(BeNil())
			Expect(toCreate).NotTo(BeEmpty())
		})

		It("does not include cross-namespace resources", func() {
			for _, obj := range toCreate {
				if _, ok := obj.(*gapiv1b1.ReferenceGrant); ok {
					Fail("ReferenceGrant should not be rendered when gateway and backend share a namespace")
				}
			}
		})

		It("renders a TLS secret in the gateway namespace", func() {
			secret := findObject[*corev1.Secret](toCreate, tlsName, gwNS)
			Expect(secret).NotTo(BeNil())
			Expect(secret.Type).To(Equal(corev1.SecretTypeTLS))
		})

		It("labels the Gateway for label-driven cleanup", func() {
			gw := findObject[*gapi.Gateway](toCreate, prefix+"-gateway", gwNS)
			Expect(gw).NotTo(BeNil())
			Expect(gw.Labels).To(HaveKeyWithValue(gateway.GatewayLabel, prefix))
		})

		It("renders a Gateway with the correct listener", func() {
			gw := findObject[*gapi.Gateway](toCreate, prefix+"-gateway", gwNS)
			Expect(gw).NotTo(BeNil())
			Expect(string(gw.Spec.GatewayClassName)).To(Equal(className))
			Expect(gw.Spec.Listeners).To(HaveLen(1))
			Expect(gw.Spec.Listeners[0].Protocol).To(Equal(gapi.HTTPSProtocolType))
			Expect(gw.Spec.Listeners[0].Port).To(Equal(gapi.PortNumber(443)))
			Expect(*gw.Spec.Listeners[0].TLS.Mode).To(Equal(gapi.TLSModeTerminate))
		})

		It("renders an HTTPRoute targeting the Backend", func() {
			route := findObject[*gapi.HTTPRoute](toCreate, prefix+"-route", gwNS)
			Expect(route).NotTo(BeNil())
			Expect(route.Spec.Rules).To(HaveLen(1))
			backendRef := route.Spec.Rules[0].BackendRefs[0]
			Expect(string(backendRef.Name)).To(Equal(prefix + "-backend"))
			Expect(*backendRef.Kind).To(Equal(gapi.Kind("Backend")))
		})

		It("renders a Backend with TLS to the service", func() {
			backend := findObject[*envoyapi.Backend](toCreate, prefix+"-backend", bkNS)
			Expect(backend).NotTo(BeNil())
			Expect(backend.Spec.Endpoints).To(HaveLen(1))
			Expect(backend.Spec.Endpoints[0].FQDN.Hostname).To(Equal(svcName + "." + bkNS + ".svc"))
			Expect(backend.Spec.Endpoints[0].FQDN.Port).To(Equal(svcPort))
			Expect(backend.Spec.TLS).NotTo(BeNil())
			Expect(backend.Spec.TLS.CACertificateRefs).To(HaveLen(1))
			Expect(string(backend.Spec.TLS.CACertificateRefs[0].Name)).To(Equal(caBundleCM))
		})
	})

	Context("extra proxy objects", func() {
		JustBeforeEach(func() {
			comp := gateway.Component(cfg)
			toCreate, toDelete = comp.Objects()
		})

		It("renders the supplied objects and the proxy NetworkPolicy", func() {
			sa := findObject[*corev1.ServiceAccount](toCreate, extraProxyName, gwNS)
			Expect(sa).NotTo(BeNil())
			np := findObject[*v3.NetworkPolicy](toCreate, networkpolicy.CalicoComponentPolicyPrefix+prefix+"-gateway-proxy", gwNS)
			Expect(np).NotTo(BeNil())
		})

		It("includes IPv4 and IPv6 ingress rules in the proxy NetworkPolicy", func() {
			np := findObject[*v3.NetworkPolicy](toCreate, networkpolicy.CalicoComponentPolicyPrefix+prefix+"-gateway-proxy", gwNS)
			Expect(np).NotTo(BeNil())
			Expect(np.Spec.Ingress).To(HaveLen(2))
			Expect(np.Spec.Ingress[0].Source.Nets).To(ConsistOf("0.0.0.0/0"))
			Expect(np.Spec.Ingress[0].Destination.Ports).To(Equal(networkpolicy.Ports(10443)))
			Expect(np.Spec.Ingress[1].Source.Nets).To(ConsistOf("::/0"))
			Expect(np.Spec.Ingress[1].Destination.Ports).To(Equal(networkpolicy.Ports(10443)))
		})

		Context("when the caller supplies none", func() {
			BeforeEach(func() {
				cfg.ExtraProxyObjects = nil
			})

			It("renders only the proxy NetworkPolicy", func() {
				for _, obj := range toCreate {
					if _, ok := obj.(*corev1.ServiceAccount); ok {
						Fail("no ServiceAccount should be rendered without extra proxy objects")
					}
					if rb, ok := obj.(*rbacv1.RoleBinding); ok && !isAccessBinding(prefix, rb.Name) {
						Fail("only the access RoleBindings should be rendered without extra proxy objects")
					}
				}
				np := findObject[*v3.NetworkPolicy](toCreate, networkpolicy.CalicoComponentPolicyPrefix+prefix+"-gateway-proxy", gwNS)
				Expect(np).NotTo(BeNil())
			})
		})
	})

	Context("cross-namespace (gateway != backend)", func() {
		BeforeEach(func() {
			cfg.GatewayNamespace = "custom-gateway-ns"
		})

		JustBeforeEach(func() {
			comp := gateway.Component(cfg)
			toCreate, toDelete = comp.Objects()
		})

		It("includes ReferenceGrant in the backend namespace", func() {
			rg := findObject[*gapiv1b1.ReferenceGrant](toCreate, prefix+"-allow-gateway", bkNS)
			Expect(rg).NotTo(BeNil())
			Expect(rg.Spec.From).To(HaveLen(1))
			Expect(string(rg.Spec.From[0].Namespace)).To(Equal("custom-gateway-ns"))
		})

		It("places each object in its own namespace", func() {
			// gwNS and bkNS differ here, so this catches a swap the same-namespace
			// context cannot: the Gateway, HTTPRoute, and TLS secret belong in the
			// gateway namespace, the Backend in the backend namespace.
			Expect(findObject[*gapi.Gateway](toCreate, prefix+"-gateway", "custom-gateway-ns")).NotTo(BeNil())
			Expect(findObject[*gapi.HTTPRoute](toCreate, prefix+"-route", "custom-gateway-ns")).NotTo(BeNil())
			Expect(findObject[*corev1.Secret](toCreate, tlsName, "custom-gateway-ns")).NotTo(BeNil())
			Expect(findObject[*envoyapi.Backend](toCreate, prefix+"-backend", bkNS)).NotTo(BeNil())

			Expect(findObject[*envoyapi.Backend](toCreate, prefix+"-backend", "custom-gateway-ns")).To(BeNil(),
				"the Backend belongs in the backend namespace, not the gateway namespace")
			Expect(findObject[*gapi.Gateway](toCreate, prefix+"-gateway", bkNS)).To(BeNil(),
				"the Gateway belongs in the gateway namespace, not the backend namespace")
		})

		It("grants each namespace only the kinds it holds", func() {
			gwAccess := prefix + "-ingressgateway-access"
			bkAccess := prefix + "-ingressgateway-backend-access"

			// The gateway namespace holds the Gateway and HTTPRoute, and must
			// not be able to write the Backend or ReferenceGrant.
			gwRole := findObject[*rbacv1.Role](toCreate, gwAccess, "custom-gateway-ns")
			Expect(gwRole).NotTo(BeNil(), "expected the gateway access Role in the gateway namespace")
			Expect(gwRole.Rules).To(HaveLen(1))
			Expect(gwRole.Rules[0].Resources).To(ConsistOf("gateways", "httproutes"))
			Expect(gwRole.Rules[0].Verbs).To(ConsistOf("create", "update", "delete"))
			Expect(findObject[*rbacv1.RoleBinding](toCreate, gwAccess, "custom-gateway-ns")).NotTo(BeNil())

			// The backend namespace holds the Backend and ReferenceGrant, and
			// must not be able to write Gateways or HTTPRoutes.
			bkRole := findObject[*rbacv1.Role](toCreate, bkAccess, bkNS)
			Expect(bkRole).NotTo(BeNil(), "expected the backend access Role in the backend namespace")
			Expect(bkRole.Rules).To(HaveLen(2))
			Expect(bkRole.Rules[0].Resources).To(ConsistOf("referencegrants"))
			Expect(bkRole.Rules[1].Resources).To(ConsistOf("backends"))
			Expect(findObject[*rbacv1.RoleBinding](toCreate, bkAccess, bkNS)).NotTo(BeNil())

			// Neither grant leaks into the other namespace.
			Expect(findObject[*rbacv1.Role](toCreate, gwAccess, bkNS)).To(BeNil(),
				"the gateway grant has no business in the backend namespace")
			Expect(findObject[*rbacv1.Role](toCreate, bkAccess, "custom-gateway-ns")).To(BeNil(),
				"the backend grant has no business in the gateway namespace")
		})

		It("leaves SA, RoleBinding, and NetworkPolicy to the GatewayAPI controller in a custom namespace", func() {
			for _, obj := range toCreate {
				switch o := obj.(type) {
				case *corev1.ServiceAccount:
					Fail("ServiceAccount should not be rendered for a custom gateway namespace")
				case *rbacv1.RoleBinding:
					Expect(o.Name).To(BeElementOf(prefix+"-ingressgateway-access", prefix+"-ingressgateway-backend-access"),
						"only the two access RoleBindings belong to this component in a custom namespace")
				case *v3.NetworkPolicy:
					Fail("NetworkPolicy should not be rendered for a custom gateway namespace")
				}
			}
		})

		It("grants write access before rendering anything it has to write", func() {
			Expect(toCreate).NotTo(BeEmpty())
			accessName := prefix + "-ingressgateway-access"
			role, ok := toCreate[0].(*rbacv1.Role)
			Expect(ok).To(BeTrue(), "the access Role must come first — nothing else can be created without it")
			Expect(role.Name).To(Equal(accessName))

			gatewayIdx, otherIdx := -1, -1
			for i, obj := range toCreate {
				switch obj.(type) {
				case *gapi.Gateway:
					gatewayIdx = i
				case *gapi.HTTPRoute, *envoyapi.Backend, *corev1.Secret:
					if otherIdx == -1 {
						otherIdx = i
					}
				}
			}
			Expect(gatewayIdx).To(BeNumerically(">=", 0))
			Expect(otherIdx).To(BeNumerically(">", gatewayIdx),
				"the Gateway carries the cleanup label, so it must precede the resources cleanup finds through it")
		})

		It("renders the ReferenceGrant before the HTTPRoute", func() {
			grantIdx, routeIdx := -1, -1
			for i, obj := range toCreate {
				switch obj.(type) {
				case *gapiv1b1.ReferenceGrant:
					grantIdx = i
				case *gapi.HTTPRoute:
					routeIdx = i
				}
			}
			Expect(grantIdx).To(BeNumerically(">=", 0))
			Expect(routeIdx).To(BeNumerically(">", grantIdx),
				"the grant must exist before the route so its cross-namespace backendRef resolves on the first pass")
		})

		It("renders the TLS secret after the Gateway", func() {
			gatewayIdx, secretIdx := -1, -1
			for i, obj := range toCreate {
				switch obj.(type) {
				case *gapi.Gateway:
					gatewayIdx = i
				case *corev1.Secret:
					secretIdx = i
				}
			}
			Expect(gatewayIdx).To(BeNumerically(">=", 0))
			Expect(secretIdx).To(BeNumerically(">", gatewayIdx),
				"the Gateway must be created before the TLS secret so the GatewayAPI controller can grant the operator secret access in the custom namespace")
		})
	})

	Context("route request timeout", func() {
		JustBeforeEach(func() {
			comp := gateway.Component(cfg)
			toCreate, toDelete = comp.Objects()
		})

		It("omits timeouts by default", func() {
			route := findObject[*gapi.HTTPRoute](toCreate, prefix+"-route", gwNS)
			Expect(route.Spec.Rules[0].Timeouts).To(BeNil())
		})

		Context("when RouteRequestTimeout is set", func() {
			BeforeEach(func() {
				cfg.RouteRequestTimeout = ptr.To("0s")
			})

			It("sets the request timeout on the route", func() {
				route := findObject[*gapi.HTTPRoute](toCreate, prefix+"-route", gwNS)
				Expect(route.Spec.Rules[0].Timeouts).NotTo(BeNil())
				Expect(*route.Spec.Rules[0].Timeouts.Request).To(Equal(gapi.Duration("0s")))
			})
		})
	})

	Context("OpenShift", func() {
		BeforeEach(func() {
			cfg.OpenShift = true
		})

		JustBeforeEach(func() {
			comp := gateway.Component(cfg)
			toCreate, toDelete = comp.Objects()
		})

		It("includes OpenShift DNS egress rules in NetworkPolicy", func() {
			np := findObject[*v3.NetworkPolicy](toCreate, networkpolicy.CalicoComponentPolicyPrefix+prefix+"-gateway-proxy", gwNS)
			Expect(np).NotTo(BeNil())
			Expect(len(np.Spec.Egress)).To(BeNumerically(">", 2))
		})
	})

	Context("component interface", func() {
		It("implements ResolveImages without error", func() {
			Expect(gateway.Component(cfg).ResolveImages(nil)).To(Succeed())
		})

		It("reports Ready", func() {
			Expect(gateway.Component(cfg).Ready()).To(BeTrue())
		})

		It("reports Linux OS type", func() {
			Expect(string(gateway.Component(cfg).SupportedOSType())).To(Equal("linux"))
		})
	})

	Context("Gateway listener hostname", func() {
		JustBeforeEach(func() {
			comp := gateway.Component(cfg)
			toCreate, toDelete = comp.Objects()
		})

		It("sets the hostname on the listener", func() {
			gw := findObject[*gapi.Gateway](toCreate, prefix+"-gateway", gwNS)
			Expect(gw.Spec.Listeners[0].Hostname).To(Equal(ptr.To(gapi.Hostname(hostname))))
		})

		It("sets AllowedRoutes to Same namespace", func() {
			gw := findObject[*gapi.Gateway](toCreate, prefix+"-gateway", gwNS)
			Expect(*gw.Spec.Listeners[0].AllowedRoutes.Namespaces.From).To(Equal(gapi.NamespacesFromSame))
		})
	})
})

var _ = Describe("Gateway deletion component", func() {
	const (
		gwNS      = "calico-system"
		bkNS      = "calico-system"
		prefix    = "calico-manager"
		tlsSecret = "calico-manager-gateway-tls"
	)

	var (
		delCfg   *gateway.DeletionConfiguration
		toCreate []client.Object
		toDelete []client.Object
	)

	BeforeEach(func() {
		delCfg = &gateway.DeletionConfiguration{
			ResourcePrefix:    prefix,
			StaleNamespace:    gwNS,
			BackendNamespace:  bkNS,
			TLSSecretName:     tlsSecret,
			ExtraProxyObjects: proxyObjects(gwNS),
		}
	})

	JustBeforeEach(func() {
		comp := gateway.DeletionComponent(delCfg)
		toCreate, toDelete = comp.Objects()
	})

	Context("same namespace", func() {
		// The deletion component is written by hand rather than derived from the
		// render, so this is what keeps the two from drifting: every object the
		// render creates must have a matching delete. The delete set may hold
		// more (a ReferenceGrant tolerated as NotFound); never less.
		It("deletes every object the render creates", func() {
			secret, err := certificatemanagement.CreateSelfSignedSecret(tlsSecret, common.OperatorNamespace(), tlsSecret, nil)
			Expect(err).NotTo(HaveOccurred())
			renderCfg := &gateway.Configuration{
				Hostname:                     "manager.example.com",
				GatewayNamespace:             gwNS,
				GatewayClassName:             "calico-gateway",
				BackendServiceName:           "calico-manager",
				BackendPort:                  9443,
				BackendNamespace:             bkNS,
				BackendCABundleConfigMapName: "tigera-ca-bundle",
				TLSKeyPair:                   certificatemanagement.NewKeyPair(secret, []string{""}, ""),
				ResourcePrefix:               prefix,
				ExtraProxyObjects:            proxyObjects(bkNS),
			}
			created, _ := gateway.Component(renderCfg).Objects()

			for _, want := range created {
				found := false
				for _, got := range toDelete {
					if reflect.TypeOf(got) == reflect.TypeOf(want) &&
						got.GetName() == want.GetName() &&
						got.GetNamespace() == want.GetNamespace() {
						found = true
						break
					}
				}
				Expect(found).To(BeTrue(), fmt.Sprintf(
					"rendered %T %s/%s has no matching delete — add it to the deletion component or it leaks on teardown",
					want, want.GetNamespace(), want.GetName()))
			}
		})

		It("returns everything in objsToDelete and nothing in objsToCreate", func() {
			Expect(toCreate).To(BeNil())
			Expect(toDelete).NotTo(BeEmpty())
		})

		It("drops the access grant last, after the resources it permits deleting", func() {
			// RoleBinding then Role, so losing the grant cannot strand an
			// earlier delete.
			last := toDelete[len(toDelete)-1]
			secondLast := toDelete[len(toDelete)-2]
			Expect(last).To(BeAssignableToTypeOf(&rbacv1.Role{}))
			Expect(secondLast).To(BeAssignableToTypeOf(&rbacv1.RoleBinding{}))
			Expect(findObject[*rbacv1.Role](toDelete, prefix+"-ingressgateway-access", gwNS)).NotTo(BeNil())
		})

		It("deletes the Gateway after the resources found through it", func() {
			gatewayIdx, lastResourceIdx := -1, -1
			for i, obj := range toDelete {
				switch obj.(type) {
				case *gapi.Gateway:
					gatewayIdx = i
				case *gapi.HTTPRoute, *envoyapi.Backend, *corev1.Secret, *v3.NetworkPolicy:
					lastResourceIdx = i
				}
			}
			Expect(gatewayIdx).To(BeNumerically(">", lastResourceIdx),
				"an earlier failed delete must leave the labeled Gateway in place so the next reconcile finds the leftovers")
		})

		It("targets the correct resource names", func() {
			names := objectNames(toDelete)
			Expect(names).To(ContainElements(
				prefix+"-gateway",
				prefix+"-route",
				prefix+"-backend",
				tlsSecret,
			))
		})

		It("deletes the backend namespace's own resources, since this component owns it", func() {
			// A default install never rendered a ReferenceGrant, but a custom-namespace
			// install did, and from here the two are indistinguishable — so the delete
			// is emitted either way and tolerated as NotFound.
			Expect(findObject[*envoyapi.Backend](toDelete, prefix+"-backend", bkNS)).NotTo(BeNil())
			Expect(findObject[*gapiv1b1.ReferenceGrant](toDelete, prefix+"-allow-gateway", bkNS)).NotTo(BeNil())
		})

		It("includes the supplied extra proxy objects", func() {
			sa := findObject[*corev1.ServiceAccount](toDelete, extraProxyName, gwNS)
			Expect(sa).NotTo(BeNil())
			np := findObject[*v3.NetworkPolicy](toDelete, networkpolicy.CalicoComponentPolicyPrefix+prefix+"-gateway-proxy", gwNS)
			Expect(np).NotTo(BeNil())
		})
	})

	Context("no extra proxy objects supplied", func() {
		BeforeEach(func() {
			delCfg.ExtraProxyObjects = nil
		})

		It("deletes only the proxy NetworkPolicy beside the access grants", func() {
			for _, obj := range toDelete {
				if _, ok := obj.(*corev1.ServiceAccount); ok {
					Fail("no ServiceAccount should be deleted without extra proxy objects")
				}
				if rb, ok := obj.(*rbacv1.RoleBinding); ok && !isAccessBinding(prefix, rb.Name) {
					Fail("only the access RoleBindings should appear without extra proxy objects")
				}
			}
			np := findObject[*v3.NetworkPolicy](toDelete, networkpolicy.CalicoComponentPolicyPrefix+prefix+"-gateway-proxy", gwNS)
			Expect(np).NotTo(BeNil())
		})
	})

	Context("cross-namespace", func() {
		BeforeEach(func() {
			delCfg.StaleNamespace = "custom-gateway-ns"
		})

		It("never reaches into the backend namespace", func() {
			// This component gives up its own grant when it finishes, so anything
			// it deleted in another namespace could 403 for the component that
			// owns that namespace — and nothing recreates grants after teardown.
			for _, obj := range toDelete {
				if obj.GetNamespace() == bkNS {
					Fail(fmt.Sprintf("cleanup for %s must not delete %T in the backend namespace",
						delCfg.StaleNamespace, obj))
				}
			}
		})

		It("leaves the Backend and ReferenceGrant to the backend namespace's own component", func() {
			Expect(findObject[*envoyapi.Backend](toDelete, prefix+"-backend", bkNS)).To(BeNil())
			Expect(findObject[*gapiv1b1.ReferenceGrant](toDelete, prefix+"-allow-gateway", bkNS)).To(BeNil())
		})

		It("does not delete GatewayAPI-controller-owned resources in a custom namespace", func() {
			for _, obj := range toDelete {
				switch o := obj.(type) {
				case *corev1.ServiceAccount:
					Fail("ServiceAccount in a custom namespace belongs to the GatewayAPI controller and must not be deleted here")
				case *rbacv1.RoleBinding:
					Expect(o.Name).To(Equal(prefix+"-ingressgateway-access"),
						"the tigera-operator-secrets RoleBinding belongs to the GatewayAPI controller and must not be deleted here")
				case *v3.NetworkPolicy:
					Fail("NetworkPolicy is not rendered for a custom namespace and must not be deleted here")
				}
			}
		})
	})

	Context("namespace move cleanup", func() {
		BeforeEach(func() {
			delCfg.StaleNamespace = "old-ns"
			delCfg.TargetNamespace = "new-ns"
		})

		It("deletes the gateway-namespace objects", func() {
			Expect(findObject[*gapi.Gateway](toDelete, prefix+"-gateway", "old-ns")).NotTo(BeNil())
			Expect(findObject[*gapi.HTTPRoute](toDelete, prefix+"-route", "old-ns")).NotTo(BeNil())
			Expect(findObject[*corev1.Secret](toDelete, tlsSecret, "old-ns")).NotTo(BeNil())
		})

		It("never deletes the Backend on a move", func() {
			for _, obj := range toDelete {
				if _, ok := obj.(*envoyapi.Backend); ok {
					Fail("Backend must not be deleted on a namespace move — the new render still routes to it")
				}
			}
		})

		It("keeps the ReferenceGrant when moving between custom namespaces", func() {
			Expect(findObject[*gapiv1b1.ReferenceGrant](toDelete, prefix+"-allow-gateway", bkNS)).To(BeNil())
		})

		It("keeps the backend grant, and drops the old namespace's gateway grant", func() {
			gwAccess := prefix + "-ingressgateway-access"
			bkAccess := prefix + "-ingressgateway-backend-access"

			Expect(findObject[*rbacv1.Role](toDelete, gwAccess, "old-ns")).NotTo(BeNil(),
				"the old namespace is no longer written to, so its gateway grant goes")
			Expect(findObject[*rbacv1.RoleBinding](toDelete, gwAccess, "old-ns")).NotTo(BeNil())

			Expect(findObject[*rbacv1.Role](toDelete, bkAccess, bkNS)).To(BeNil(),
				"the Backend and ReferenceGrant stay on a move, so the grant that writes them stays too")
			Expect(findObject[*rbacv1.RoleBinding](toDelete, bkAccess, bkNS)).To(BeNil())
		})

		Context("moving out of the backend namespace", func() {
			BeforeEach(func() {
				// Whisker's default: gateway and backend share a namespace, and
				// the gateway is the thing leaving.
				delCfg.StaleNamespace = bkNS
				delCfg.TargetNamespace = "new-ns"
			})

			It("keeps the backend grant even though the namespace is the one being cleaned", func() {
				Expect(findObject[*rbacv1.Role](toDelete, prefix+"-ingressgateway-backend-access", bkNS)).To(BeNil(),
					"the Backend is still here, so its grant must survive the move")
				Expect(findObject[*rbacv1.RoleBinding](toDelete, prefix+"-ingressgateway-backend-access", bkNS)).To(BeNil())
			})

			It("still drops the gateway grant, which has nothing left to write here", func() {
				Expect(findObject[*rbacv1.Role](toDelete, prefix+"-ingressgateway-access", bkNS)).NotTo(BeNil())
			})
		})

		Context("moving into the backend namespace", func() {
			BeforeEach(func() {
				// The stale namespace is the custom one the gateway is leaving,
				// distinct from the backend namespace it moves into — so the
				// staleNS != bkNS path is actually exercised.
				delCfg.StaleNamespace = "custom-gateway-ns"
				delCfg.TargetNamespace = bkNS
			})

			It("leaves the ReferenceGrant to the live render, which holds the backend grant", func() {
				// A stale pass for the old gateway namespace has no write access
				// in the backend namespace, so it must not try to delete there.
				Expect(findObject[*gapiv1b1.ReferenceGrant](toDelete, prefix+"-allow-gateway", bkNS)).To(BeNil())
			})

			It("still keeps the backend grant", func() {
				// The new render writes the Backend there, so the grant stays.
				accessName := prefix + "-ingressgateway-access"
				Expect(findObject[*rbacv1.Role](toDelete, accessName, bkNS)).To(BeNil())
				Expect(findObject[*rbacv1.RoleBinding](toDelete, accessName, bkNS)).To(BeNil())
			})
		})

		Context("moving out of the backend namespace", func() {
			BeforeEach(func() {
				delCfg.StaleNamespace = bkNS
				delCfg.TargetNamespace = "new-ns"
			})

			It("deletes the supplied proxy objects and NetworkPolicy from the backend namespace", func() {
				Expect(findObject[*corev1.ServiceAccount](toDelete, extraProxyName, bkNS)).NotTo(BeNil())
				np := findObject[*v3.NetworkPolicy](toDelete, networkpolicy.CalicoComponentPolicyPrefix+prefix+"-gateway-proxy", bkNS)
				Expect(np).NotTo(BeNil())
			})

			It("still keeps the Backend", func() {
				for _, obj := range toDelete {
					if _, ok := obj.(*envoyapi.Backend); ok {
						Fail("Backend must not be deleted on a namespace move")
					}
				}
			})
		})
	})

	Context("component interface", func() {
		It("implements ResolveImages without error", func() {
			Expect(gateway.DeletionComponent(delCfg).ResolveImages(nil)).To(Succeed())
		})

		It("reports Ready", func() {
			Expect(gateway.DeletionComponent(delCfg).Ready()).To(BeTrue())
		})
	})
})

// extraProxyName names the fixture objects the tests hand ExtraProxyObjects.
const extraProxyName = "extra-proxy-object"

// proxyObjects are fixtures for the objects a variant hands
// Configuration.ExtraProxyObjects, which the component only passes through.
func proxyObjects(namespace string) []client.Object {
	return []client.Object{
		&corev1.ServiceAccount{
			TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: extraProxyName, Namespace: namespace},
		},
		&rbacv1.RoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: extraProxyName, Namespace: namespace},
		},
	}
}

func findObject[T client.Object](objs []client.Object, name, ns string) T {
	for _, obj := range objs {
		if t, ok := obj.(T); ok && obj.GetName() == name && obj.GetNamespace() == ns {
			return t
		}
	}
	var zero T
	return zero
}

func objectNames(objs []client.Object) []string {
	names := make([]string, len(objs))
	for i, obj := range objs {
		names[i] = obj.GetName()
	}
	return names
}

// isAccessBinding reports whether name is one of the two grants this component
// renders for itself, rather than a RoleBinding belonging to something else.
func isAccessBinding(prefix, name string) bool {
	return name == prefix+"-ingressgateway-access" || name == prefix+"-ingressgateway-backend-access"
}
