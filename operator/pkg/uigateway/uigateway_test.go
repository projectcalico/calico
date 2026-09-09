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

package uigateway_test

import (
	"context"

	envoyapi "github.com/envoyproxy/gateway/api/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gapi "sigs.k8s.io/gateway-api/apis/v1"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/apis"
	"github.com/projectcalico/calico/operator/pkg/common"
	ctrlrfake "github.com/projectcalico/calico/operator/pkg/ctrlruntime/client/fake"
	"github.com/projectcalico/calico/operator/pkg/render"
	rgateway "github.com/projectcalico/calico/operator/pkg/render/gateway"
	"github.com/projectcalico/calico/operator/pkg/tls/certificatemanagement"
	"github.com/projectcalico/calico/operator/pkg/uigateway"
)

var _ = Describe("UnhealthyReason", func() {
	const ns = "calico-system"

	var (
		ctx context.Context
		h   *uigateway.Helper
	)

	cond := func(t string, status metav1.ConditionStatus, msg string) metav1.Condition {
		return metav1.Condition{Type: t, Status: status, Message: msg, Reason: "Test", LastTransitionTime: metav1.Now()}
	}

	newGateway := func(conds ...metav1.Condition) *gapi.Gateway {
		return &gapi.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "calico-manager-gateway", Namespace: ns},
			Status:     gapi.GatewayStatus{Conditions: conds},
		}
	}

	newRoute := func(conds ...metav1.Condition) *gapi.HTTPRoute {
		route := &gapi.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "calico-manager-route", Namespace: ns},
		}
		if len(conds) > 0 {
			route.Status.Parents = []gapi.RouteParentStatus{{Conditions: conds}}
		}
		return route
	}

	healthyGateway := func() *gapi.Gateway {
		return newGateway(
			cond(string(gapi.GatewayConditionAccepted), metav1.ConditionTrue, ""),
			cond(string(gapi.GatewayConditionProgrammed), metav1.ConditionTrue, ""),
		)
	}

	build := func(objs ...client.Object) {
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		cli := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(objs...).Build()
		h = uigateway.NewHelper(cli, uigateway.Config{ResourcePrefix: "calico-manager"})
	}

	BeforeEach(func() {
		ctx = context.Background()
	})

	It("reports a missing Gateway", func() {
		build()
		Expect(h.UnhealthyReason(ctx, ns)).To(ContainSubstring("not found yet"))
	})

	It("reports Gateway not accepted", func() {
		build(newGateway(cond(string(gapi.GatewayConditionAccepted), metav1.ConditionFalse, "invalid listener")))
		Expect(h.UnhealthyReason(ctx, ns)).To(Equal("Gateway not accepted: invalid listener"))
	})

	It("reports Gateway not programmed", func() {
		build(newGateway(
			cond(string(gapi.GatewayConditionAccepted), metav1.ConditionTrue, ""),
			cond(string(gapi.GatewayConditionProgrammed), metav1.ConditionFalse, "no addresses assigned"),
		))
		Expect(h.UnhealthyReason(ctx, ns)).To(Equal("Gateway not programmed: no addresses assigned"))
	})

	It("reports a Gateway whose conditions have not been published yet", func() {
		build(newGateway(), newRoute())
		Expect(h.UnhealthyReason(ctx, ns)).To(ContainSubstring("not reported yet"))
	})

	It("reports an HTTPRoute that no parent has accepted yet", func() {
		build(healthyGateway(), newRoute())
		Expect(h.UnhealthyReason(ctx, ns)).To(ContainSubstring("not accepted by any parent yet"))
	})

	It("reports a missing HTTPRoute once the Gateway is healthy", func() {
		build(healthyGateway())
		Expect(h.UnhealthyReason(ctx, ns)).To(ContainSubstring("HTTPRoute"))
		Expect(h.UnhealthyReason(ctx, ns)).To(ContainSubstring("not found yet"))
	})

	It("reports HTTPRoute not accepted", func() {
		build(healthyGateway(), newRoute(cond(string(gapi.RouteConditionAccepted), metav1.ConditionFalse, "no matching parent")))
		Expect(h.UnhealthyReason(ctx, ns)).To(Equal("HTTPRoute not accepted: no matching parent"))
	})

	It("reports HTTPRoute refs not resolved", func() {
		build(healthyGateway(), newRoute(
			cond(string(gapi.RouteConditionAccepted), metav1.ConditionTrue, ""),
			cond(string(gapi.RouteConditionResolvedRefs), metav1.ConditionFalse, "backend not permitted"),
		))
		Expect(h.UnhealthyReason(ctx, ns)).To(Equal("HTTPRoute refs not resolved: backend not permitted"))
	})

	It("returns empty when the Gateway and HTTPRoute are healthy", func() {
		build(healthyGateway(), newRoute(
			cond(string(gapi.RouteConditionAccepted), metav1.ConditionTrue, ""),
			cond(string(gapi.RouteConditionResolvedRefs), metav1.ConditionTrue, ""),
		))
		Expect(h.UnhealthyReason(ctx, ns)).To(BeEmpty())
	})
})

var _ = Describe("Cleanup helpers", func() {
	const (
		prefix    = "calico-whisker"
		backendNS = "calico-system"
	)

	var (
		ctx context.Context
		cli client.Client
		h   *uigateway.Helper
		cfg uigateway.Config
	)

	labeledGateway := func(name, ns string) *gapi.Gateway {
		return &gapi.Gateway{ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			Labels:    map[string]string{rgateway.GatewayLabel: prefix},
		}}
	}

	build := func(objs ...client.Object) {
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		mapper := apimeta.NewDefaultRESTMapper(nil)
		mapper.Add(schema.GroupVersionKind{Group: gapi.GroupName, Version: "v1", Kind: "Gateway"}, apimeta.RESTScopeNamespace)
		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(objs...).WithRESTMapper(mapper).Build()
		cfg = uigateway.Config{
			ResourcePrefix:   prefix,
			TLSSecretName:    prefix + "-gateway-tls",
			BackendNamespace: backendNS,
		}
		h = uigateway.NewHelper(cli, cfg)
	}

	// deletionNamespaces collects, per object type, the namespaces the given
	// components mark for deletion.
	deletionNamespaces := func(components []render.Component) (gateways, backends []string) {
		for _, c := range components {
			_, toDelete := c.Objects()
			for _, obj := range toDelete {
				switch obj.(type) {
				case *gapi.Gateway:
					gateways = append(gateways, obj.GetNamespace())
				case *envoyapi.Backend:
					backends = append(backends, obj.GetNamespace())
				}
			}
		}
		return
	}

	BeforeEach(func() {
		ctx = context.Background()
	})

	Describe("Namespaces", func() {
		It("returns sorted, de-duplicated namespaces of labeled Gateways", func() {
			build(
				labeledGateway("gw-1", "ns-b"),
				labeledGateway("gw-2", "ns-a"),
				labeledGateway("gw-3", "ns-a"),
			)
			namespaces, err := h.Namespaces(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(namespaces).To(Equal([]string{"ns-a", "ns-b"}))
		})

		It("ignores Gateways carrying another component's label or no label", func() {
			other := labeledGateway("gw-other", "ns-c")
			other.Labels[rgateway.GatewayLabel] = "calico-manager"
			unlabeled := &gapi.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "gw-user", Namespace: "ns-d"}}
			build(labeledGateway("gw-1", "ns-a"), other, unlabeled)

			namespaces, err := h.Namespaces(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(namespaces).To(Equal([]string{"ns-a"}))
		})

		It("returns empty, not an error, when the Gateway kind is not served", func() {
			build()
			h = uigateway.NewHelper(noGatewayKindClient{cli}, cfg)
			namespaces, err := h.Namespaces(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(namespaces).To(BeEmpty())
		})
	})

	Describe("StaleComponents", func() {
		It("returns deletion components only for namespaces outside the desired one", func() {
			build(
				labeledGateway(prefix+"-gateway", "ns-a"),
				labeledGateway(prefix+"-gateway", backendNS),
			)
			components, err := h.StaleComponents(ctx, backendNS)
			Expect(err).NotTo(HaveOccurred())
			Expect(components).To(HaveLen(1))

			gateways, backends := deletionNamespaces(components)
			Expect(gateways).To(Equal([]string{"ns-a"}))
			// The Backend stays: it lives in the backend namespace and the new
			// render still routes to it.
			Expect(backends).To(BeEmpty())
		})

		It("returns nothing when every labeled Gateway is in the desired namespace", func() {
			build(labeledGateway(prefix+"-gateway", backendNS))
			components, err := h.StaleComponents(ctx, backendNS)
			Expect(err).NotTo(HaveOccurred())
			Expect(components).To(BeEmpty())
		})
	})

	Describe("Teardown", func() {
		It("tears down every labeled Gateway's namespace plus the backend namespace", func() {
			build(labeledGateway(prefix+"-gateway", "ns-a"))
			components, err := h.Teardown(ctx)
			Expect(err).NotTo(HaveOccurred())

			gateways, backends := deletionNamespaces(components)
			Expect(gateways).To(ConsistOf("ns-a", backendNS))
			// The Backend lives in the backend namespace, so only that
			// namespace's component deletes it. If ns-a's component deleted it
			// too, it would be reaching into a namespace whose grant it may
			// already have dropped, and the delete would 403 with nothing left
			// to restore the grant.
			Expect(backends).To(ConsistOf(backendNS))
		})

		It("deletes nothing when no labeled Gateway exists", func() {
			build()
			components, err := h.Teardown(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(components).To(BeEmpty(),
				"the Gateway is rendered first, so without one nothing of ours is on the cluster and the Backend's kind may not even be served")
		})

		It("returns nothing when the gateway CRDs are absent", func() {
			build()
			h = uigateway.NewHelper(noGatewayKindClient{cli}, cfg)
			components, err := h.Teardown(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(components).To(BeEmpty())
		})

		// deletedNamespaces collects the Namespace objects the components delete.
		deletedNamespaces := func(components []render.Component) []string {
			var names []string
			for _, c := range components {
				_, toDelete := c.Objects()
				for _, obj := range toDelete {
					if _, ok := obj.(*corev1.Namespace); ok {
						names = append(names, obj.GetName())
					}
				}
			}
			return names
		}

		It("deletes a namespace the operator created, and only that one", func() {
			build(
				labeledGateway(prefix+"-gateway", "ns-ours"),
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
					Name:   "ns-ours",
					Labels: map[string]string{rgateway.GatewayNamespaceLabel: "true"},
				}},
			)
			components, err := h.Teardown(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(deletedNamespaces(components)).To(ConsistOf("ns-ours"),
				"the backend namespace belongs to another controller and must survive")
		})

		It("keeps a shared namespace while another component's Gateway remains", func() {
			foreign := labeledGateway("calico-manager-gateway", "ns-shared")
			foreign.Labels[rgateway.GatewayLabel] = "calico-manager"
			build(
				labeledGateway(prefix+"-gateway", "ns-shared"),
				foreign,
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
					Name:   "ns-shared",
					Labels: map[string]string{rgateway.GatewayNamespaceLabel: "true"},
				}},
			)
			components, err := h.Teardown(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(deletedNamespaces(components)).NotTo(ContainElement("ns-shared"),
				"another component's Gateway still lives here, so the namespace must survive")
		})

		It("never deletes a namespace the user created", func() {
			build(
				labeledGateway(prefix+"-gateway", "ns-theirs"),
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
					Name:   "ns-theirs",
					Labels: map[string]string{"team": "netsec"},
				}},
			)
			components, err := h.Teardown(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(deletedNamespaces(components)).To(BeEmpty(),
				"an unlabeled namespace may hold user workloads")
		})
	})

	Describe("Components", func() {
		gatewayAPI := func(classes ...string) *operatorv1.GatewayAPI {
			gwapi := &operatorv1.GatewayAPI{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
			for _, c := range classes {
				gwapi.Spec.GatewayClasses = append(gwapi.Spec.GatewayClasses, operatorv1.GatewayClassSpec{Name: c})
			}
			return gwapi
		}
		spec := func(gwNS string) *operatorv1.IngressGatewaySpec {
			return &operatorv1.IngressGatewaySpec{Hostname: "ui.example.com", GatewayNamespace: &gwNS}
		}
		keyPair := func() certificatemanagement.KeyPairInterface {
			secret, err := certificatemanagement.CreateSelfSignedSecret(prefix+"-gateway-tls", common.OperatorNamespace(), prefix, nil)
			Expect(err).NotTo(HaveOccurred())
			return certificatemanagement.NewKeyPair(secret, []string{""}, "")
		}

		// createdNamespace finds the Namespace object the components render, or
		// nil when none is rendered.
		createdNamespace := func(components []render.Component, name string) *corev1.Namespace {
			for _, c := range components {
				toCreate, _ := c.Objects()
				for _, obj := range toCreate {
					if ns, ok := obj.(*corev1.Namespace); ok && ns.GetName() == name {
						return ns
					}
				}
			}
			return nil
		}

		It("creates an OpenShift gateway namespace the proxy can run in", func() {
			build(gatewayAPI("tigera-gateway-class"))
			cfgOCP := cfg
			cfgOCP.Provider = operatorv1.ProviderOpenShift
			h = uigateway.NewHelper(cli, cfgOCP)
			components, err := h.Components(ctx, spec("ns-a"), keyPair())
			Expect(err).NotTo(HaveOccurred())

			ns := createdNamespace(components, "ns-a")
			Expect(ns).NotTo(BeNil())
			Expect(ns.Labels).To(HaveKeyWithValue("openshift.io/run-level", "0"),
				"without this the Envoy proxy pod fails SCC admission in a fresh namespace")
			Expect(ns.Labels).To(HaveKeyWithValue(rgateway.GatewayNamespaceLabel, "true"))
		})

		It("creates an AKS gateway namespace with the Azure-policy label", func() {
			build(gatewayAPI("tigera-gateway-class"))
			cfgAKS := cfg
			cfgAKS.Provider = operatorv1.ProviderAKS
			h = uigateway.NewHelper(cli, cfgAKS)
			components, err := h.Components(ctx, spec("ns-a"), keyPair())
			Expect(err).NotTo(HaveOccurred())

			ns := createdNamespace(components, "ns-a")
			Expect(ns).NotTo(BeNil())
			// Matches every other operator-created namespace on AKS; without it
			// Azure Policy differs for the gateway namespace.
			Expect(ns.Labels).To(HaveKeyWithValue("control-plane", "true"))
			Expect(ns.Labels).To(HaveKeyWithValue(rgateway.GatewayNamespaceLabel, "true"))
		})

		It("creates the gateway namespace stamped with the ownership label", func() {
			build(gatewayAPI("tigera-gateway-class"))
			components, err := h.Components(ctx, spec("ns-a"), keyPair())
			Expect(err).NotTo(HaveOccurred())

			ns := createdNamespace(components, "ns-a")
			Expect(ns).NotTo(BeNil())
			Expect(ns.Labels).To(HaveKeyWithValue(rgateway.GatewayNamespaceLabel, "true"),
				"the marker is what lets teardown delete only a namespace the operator created")
			Expect(ns.OwnerReferences).To(BeEmpty())
		})

		It("leaves an existing namespace untouched and unlabeled", func() {
			build(gatewayAPI("tigera-gateway-class"), &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "ns-a",
					Labels: map[string]string{"team": "netsec"},
				},
			})
			components, err := h.Components(ctx, spec("ns-a"), keyPair())
			Expect(err).NotTo(HaveOccurred())

			Expect(createdNamespace(components, "ns-a")).To(BeNil(),
				"a user namespace must never be re-rendered with the ownership label, or teardown would delete it")
			ns := &corev1.Namespace{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: "ns-a"}, ns)).NotTo(HaveOccurred())
			Expect(ns.Labels).To(Equal(map[string]string{"team": "netsec"}),
				"the existing namespace is read only, never written")
		})

		It("does not create the backend namespace, which another controller owns", func() {
			build(gatewayAPI("tigera-gateway-class"))
			components, err := h.Components(ctx, spec(backendNS), keyPair())
			Expect(err).NotTo(HaveOccurred())
			Expect(createdNamespace(components, backendNS)).To(BeNil())
		})

		It("reports a missing GatewayAPI CR with a message naming the prerequisite", func() {
			build()
			_, err := h.Components(ctx, spec("ns-a"), keyPair())
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("GatewayAPI CR not found"))
		})

		It("reports an ambiguous GatewayClass", func() {
			build(gatewayAPI("class-a", "class-b"))
			_, err := h.Components(ctx, spec("ns-a"), keyPair())
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("multiple GatewayClasses"))
		})

		It("refuses the operator namespace as the gateway namespace", func() {
			build(gatewayAPI("tigera-gateway-class"))
			_, err := h.Components(ctx, spec(common.OperatorNamespace()), keyPair())
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("cannot be the operator namespace"))
		})

		It("refuses to render under certificateManagement", func() {
			build(gatewayAPI("tigera-gateway-class"))
			cmKeyPair := &certificatemanagement.KeyPair{CertificateManagement: &operatorv1.CertificateManagement{}}
			components, err := h.Components(ctx, spec("ns-a"), cmKeyPair)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("certificateManagement"))
			Expect(createdNamespace(components, "ns-a")).To(BeNil(),
				"nothing should be rendered when the render is refused")
		})
	})
})

// noGatewayKindClient simulates a cluster without the Gateway API CRDs: listing
// Gateways fails with NoKindMatchError, everything else passes through.
type noGatewayKindClient struct {
	client.Client
}

func (c noGatewayKindClient) RESTMapper() apimeta.RESTMapper {
	return apimeta.NewDefaultRESTMapper(nil)
}

func (c noGatewayKindClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if _, ok := list.(*gapi.GatewayList); ok {
		return &apimeta.NoKindMatchError{GroupKind: schema.GroupKind{Group: "gateway.networking.k8s.io", Kind: "Gateway"}}
	}
	return c.Client.List(ctx, list, opts...)
}
