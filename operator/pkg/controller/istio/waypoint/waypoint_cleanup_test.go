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

package waypoint

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gapi "sigs.k8s.io/gateway-api/apis/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/controller/utils"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
)

var _ = Describe("Waypoint controller stale gateway set tests", func() {
	const (
		istioClassName = "istio"
		userNamespace  = "user-ns"
		gatewayName    = "waypoint"
		gatewayUID     = types.UID("11111111-2222-3333-4444-555555555555")
	)

	var (
		cli     client.Client
		scheme  *runtime.Scheme
		ctx     context.Context
		r       *ReconcileWaypoint
		istioCR *operatorv1.Istio
	)

	BeforeEach(func() {
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).ShouldNot(HaveOccurred())

		ctx = context.Background()
		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

		gatewayWatchReady := &utils.ReadyFlag{}
		gatewayWatchReady.MarkAsReady()

		r = &ReconcileWaypoint{
			Client:            cli,
			scheme:            scheme,
			gatewayWatchReady: gatewayWatchReady,
		}

		istioCR = &operatorv1.Istio{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
			},
		}
	})

	createIstioCR := func() {
		Expect(cli.Create(ctx, istioCR)).NotTo(HaveOccurred())
	}

	createGateway := func(name, namespace, class string, uid types.UID) {
		gw := &gapi.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
				UID:       uid,
			},
			Spec: gapi.GatewaySpec{
				GatewayClassName: gapi.ObjectName(class),
				Listeners: []gapi.Listener{
					{
						Name:     "mesh",
						Port:     15008,
						Protocol: gapi.ProtocolType("HBONE"),
					},
				},
			},
		}
		Expect(cli.Create(ctx, gw)).NotTo(HaveOccurred())
	}

	// gatewaySetMeta mirrors the metadata istiod stamps on the resources it
	// renders for a Gateway: the istio-waypoint class uses the Gateway's name
	// as-is, other classes append the class name.
	gatewaySetMeta := func(gwName, namespace, class string, uid types.UID) metav1.ObjectMeta {
		name := gwName
		if class != IstioWaypointClassName {
			name = gwName + "-" + class
		}
		return metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				"gateway.networking.k8s.io/gateway-name": gwName,
				GatewayClassNameLabel:                    class,
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "gateway.networking.k8s.io/v1beta1",
					Kind:       "Gateway",
					Name:       gwName,
					UID:        uid,
				},
			},
		}
	}

	createGatewaySet := func(gwName, namespace, class string, uid types.UID) {
		Expect(cli.Create(ctx, &appsv1.Deployment{ObjectMeta: gatewaySetMeta(gwName, namespace, class, uid)})).NotTo(HaveOccurred())
		Expect(cli.Create(ctx, &corev1.Service{ObjectMeta: gatewaySetMeta(gwName, namespace, class, uid)})).NotTo(HaveOccurred())
		Expect(cli.Create(ctx, &corev1.ServiceAccount{ObjectMeta: gatewaySetMeta(gwName, namespace, class, uid)})).NotTo(HaveOccurred())
		Expect(cli.Create(ctx, &policyv1.PodDisruptionBudget{ObjectMeta: gatewaySetMeta(gwName, namespace, class, uid)})).NotTo(HaveOccurred())
	}

	doReconcile := func() {
		_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default"}})
		Expect(err).ShouldNot(HaveOccurred())
	}

	// remainingSetNames returns the names of the resources of each kind still
	// present in the user namespace.
	remainingSetNames := func() map[string][]string {
		remaining := map[string][]string{}

		deployments := &appsv1.DeploymentList{}
		Expect(cli.List(ctx, deployments, client.InNamespace(userNamespace))).NotTo(HaveOccurred())
		for _, d := range deployments.Items {
			remaining["Deployment"] = append(remaining["Deployment"], d.Name)
		}

		services := &corev1.ServiceList{}
		Expect(cli.List(ctx, services, client.InNamespace(userNamespace))).NotTo(HaveOccurred())
		for _, s := range services.Items {
			remaining["Service"] = append(remaining["Service"], s.Name)
		}

		serviceAccounts := &corev1.ServiceAccountList{}
		Expect(cli.List(ctx, serviceAccounts, client.InNamespace(userNamespace))).NotTo(HaveOccurred())
		for _, s := range serviceAccounts.Items {
			remaining["ServiceAccount"] = append(remaining["ServiceAccount"], s.Name)
		}

		pdbs := &policyv1.PodDisruptionBudgetList{}
		Expect(cli.List(ctx, pdbs, client.InNamespace(userNamespace))).NotTo(HaveOccurred())
		for _, p := range pdbs.Items {
			remaining["PodDisruptionBudget"] = append(remaining["PodDisruptionBudget"], p.Name)
		}

		return remaining
	}

	Context("when a Gateway's class has changed", func() {
		It("should delete the stale istio-waypoint set and keep the current set", func() {
			createIstioCR()
			// The Gateway was flipped from istio-waypoint to istio: the stale
			// set carries the istio-waypoint class label, the current set the
			// istio class label.
			createGateway(gatewayName, userNamespace, istioClassName, gatewayUID)
			createGatewaySet(gatewayName, userNamespace, IstioWaypointClassName, gatewayUID)
			createGatewaySet(gatewayName, userNamespace, istioClassName, gatewayUID)

			doReconcile()

			remaining := remainingSetNames()
			for _, kind := range []string{"Deployment", "Service", "ServiceAccount", "PodDisruptionBudget"} {
				Expect(remaining[kind]).To(ConsistOf("waypoint-istio"), "stale %s should be deleted", kind)
			}
		})

		It("should delete the stale istio set when flipping back to istio-waypoint", func() {
			createIstioCR()
			createGateway(gatewayName, userNamespace, IstioWaypointClassName, gatewayUID)
			createGatewaySet(gatewayName, userNamespace, IstioWaypointClassName, gatewayUID)
			createGatewaySet(gatewayName, userNamespace, istioClassName, gatewayUID)

			doReconcile()

			remaining := remainingSetNames()
			for _, kind := range []string{"Deployment", "Service", "ServiceAccount", "PodDisruptionBudget"} {
				Expect(remaining[kind]).To(ConsistOf("waypoint"), "stale %s should be deleted", kind)
			}
		})
	})

	Context("when a Gateway's class matches its resources", func() {
		It("should not delete anything", func() {
			createIstioCR()
			createGateway(gatewayName, userNamespace, IstioWaypointClassName, gatewayUID)
			createGatewaySet(gatewayName, userNamespace, IstioWaypointClassName, gatewayUID)

			doReconcile()

			remaining := remainingSetNames()
			for _, kind := range []string{"Deployment", "Service", "ServiceAccount", "PodDisruptionBudget"} {
				Expect(remaining[kind]).To(ConsistOf("waypoint"), "%s should be kept", kind)
			}
		})
	})

	Context("when the owning Gateway no longer exists", func() {
		It("should leave the resources to Kubernetes garbage collection", func() {
			createIstioCR()
			createGatewaySet(gatewayName, userNamespace, IstioWaypointClassName, gatewayUID)

			doReconcile()

			remaining := remainingSetNames()
			for _, kind := range []string{"Deployment", "Service", "ServiceAccount", "PodDisruptionBudget"} {
				Expect(remaining[kind]).To(ConsistOf("waypoint"), "%s should be left to GC", kind)
			}
		})
	})

	Context("when the owner reference UID does not match the Gateway", func() {
		It("should leave the resources to Kubernetes garbage collection", func() {
			createIstioCR()
			createGateway(gatewayName, userNamespace, istioClassName, gatewayUID)
			createGatewaySet(gatewayName, userNamespace, IstioWaypointClassName, types.UID("99999999-9999-9999-9999-999999999999"))

			doReconcile()

			remaining := remainingSetNames()
			for _, kind := range []string{"Deployment", "Service", "ServiceAccount", "PodDisruptionBudget"} {
				Expect(remaining[kind]).To(ConsistOf("waypoint"), "%s should be left to GC", kind)
			}
		})
	})

	Context("when the stale class is not istiod-managed", func() {
		It("should not delete resources of another gateway implementation", func() {
			createIstioCR()
			gc := &gapi.GatewayClass{
				ObjectMeta: metav1.ObjectMeta{Name: "other-class"},
				Spec: gapi.GatewayClassSpec{
					ControllerName: "example.com/gateway-controller",
				},
			}
			Expect(cli.Create(ctx, gc)).NotTo(HaveOccurred())

			createGateway(gatewayName, userNamespace, istioClassName, gatewayUID)
			createGatewaySet(gatewayName, userNamespace, "other-class", gatewayUID)

			doReconcile()

			Expect(remainingSetNames()["Deployment"]).To(ConsistOf("waypoint-other-class"))
		})
	})

	Context("when the stale class is a non-builtin istiod-managed class", func() {
		It("should delete the stale set", func() {
			createIstioCR()
			gc := &gapi.GatewayClass{
				ObjectMeta: metav1.ObjectMeta{Name: "custom-waypoint"},
				Spec: gapi.GatewayClassSpec{
					ControllerName: "istio.io/mesh-controller",
				},
			}
			Expect(cli.Create(ctx, gc)).NotTo(HaveOccurred())

			createGateway(gatewayName, userNamespace, IstioWaypointClassName, gatewayUID)
			createGatewaySet(gatewayName, userNamespace, "custom-waypoint", gatewayUID)
			createGatewaySet(gatewayName, userNamespace, IstioWaypointClassName, gatewayUID)

			doReconcile()

			Expect(remainingSetNames()["Deployment"]).To(ConsistOf("waypoint"))
		})
	})

	Context("when resources are not labeled with a gateway class", func() {
		It("should not delete them", func() {
			createIstioCR()
			createGateway(gatewayName, userNamespace, istioClassName, gatewayUID)

			// A user Deployment that happens to have an owner reference to the
			// Gateway but was not rendered by istiod (no class label).
			d := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "user-deployment",
					Namespace: userNamespace,
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: "gateway.networking.k8s.io/v1beta1",
							Kind:       "Gateway",
							Name:       gatewayName,
							UID:        gatewayUID,
						},
					},
				},
			}
			Expect(cli.Create(ctx, d)).NotTo(HaveOccurred())

			doReconcile()

			Expect(remainingSetNames()["Deployment"]).To(ConsistOf("user-deployment"))
		})
	})

	Context("when the Istio CR does not exist", func() {
		It("should not delete anything", func() {
			createGateway(gatewayName, userNamespace, istioClassName, gatewayUID)
			createGatewaySet(gatewayName, userNamespace, IstioWaypointClassName, gatewayUID)

			doReconcile()

			Expect(remainingSetNames()["Deployment"]).To(ConsistOf("waypoint"))
		})
	})

	Context("when the Istio CR is being deleted", func() {
		It("should not delete anything", func() {
			istioCR.Finalizers = []string{"tigera.io/test-finalizer"}
			createIstioCR()
			Expect(cli.Delete(ctx, istioCR)).NotTo(HaveOccurred())

			createGateway(gatewayName, userNamespace, istioClassName, gatewayUID)
			createGatewaySet(gatewayName, userNamespace, IstioWaypointClassName, gatewayUID)

			doReconcile()

			Expect(remainingSetNames()["Deployment"]).To(ConsistOf("waypoint"))
		})
	})

	Context("when the Gateway watch is not yet ready", func() {
		It("should not delete anything", func() {
			r.gatewayWatchReady = &utils.ReadyFlag{}

			createIstioCR()
			createGateway(gatewayName, userNamespace, istioClassName, gatewayUID)
			createGatewaySet(gatewayName, userNamespace, IstioWaypointClassName, gatewayUID)

			doReconcile()

			Expect(remainingSetNames()["Deployment"]).To(ConsistOf("waypoint"))
		})
	})
})
