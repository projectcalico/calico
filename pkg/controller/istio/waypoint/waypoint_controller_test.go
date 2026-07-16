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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gapi "sigs.k8s.io/gateway-api/apis/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/utils"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
)

var _ = Describe("Waypoint controller pull secret tests", func() {
	var (
		cli          client.Client
		scheme       *runtime.Scheme
		ctx          context.Context
		r            *ReconcileWaypoint
		installation *operatorv1.Installation
		istioCR      *operatorv1.Istio
	)

	BeforeEach(func() {
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).ShouldNot(HaveOccurred())

		ctx = context.Background()
		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

		// Create certificate manager prerequisites.
		certificateManager, err := certificatemanager.Create(cli, nil, "cluster.local", common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())
		Expect(cli.Create(ctx, certificateManager.KeyPair().Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

		gatewayWatchReady := &utils.ReadyFlag{}
		gatewayWatchReady.MarkAsReady()

		r = &ReconcileWaypoint{
			Client:            cli,
			scheme:            scheme,
			gatewayWatchReady: gatewayWatchReady,
		}

		installation = &operatorv1.Installation{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
			},
			Spec: operatorv1.InstallationSpec{
				Variant: operatorv1.Calico,
			},
			Status: operatorv1.InstallationStatus{
				Variant: operatorv1.Calico,
			},
		}

		istioCR = &operatorv1.Istio{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
			},
		}
	})

	createNamespace := func(name string) {
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
		err := cli.Create(ctx, ns)
		if err == nil {
			return
		}
		// Ignore already-exists
		Expect(client.IgnoreAlreadyExists(err)).ShouldNot(HaveOccurred())
	}

	createPullSecret := func(name string) {
		s := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: common.OperatorNamespace(),
			},
			Data: map[string][]byte{
				".dockerconfigjson": []byte(`{"auths":{"registry.example.com":{"auth":"dGVzdDp0ZXN0"}}}`),
			},
			Type: corev1.SecretTypeDockerConfigJson,
		}
		Expect(cli.Create(ctx, s)).NotTo(HaveOccurred())
	}

	createWaypointGateway := func(name, namespace string) {
		createNamespace(namespace)
		gw := &gapi.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
			},
			Spec: gapi.GatewaySpec{
				GatewayClassName: gapi.ObjectName(IstioWaypointClassName),
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

	createNonWaypointGateway := func(name, namespace string) {
		createNamespace(namespace)
		gw := &gapi.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
			},
			Spec: gapi.GatewaySpec{
				GatewayClassName: "some-other-class",
				Listeners: []gapi.Listener{
					{
						Name:     "http",
						Port:     80,
						Protocol: gapi.HTTPProtocolType,
					},
				},
			},
		}
		Expect(cli.Create(ctx, gw)).NotTo(HaveOccurred())
	}

	doReconcile := func() (reconcile.Result, error) {
		return r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default"}})
	}

	listTrackedSecrets := func() []corev1.Secret {
		secretList := &corev1.SecretList{}
		err := cli.List(ctx, secretList, client.MatchingLabels{WaypointPullSecretLabel: "true"})
		Expect(err).NotTo(HaveOccurred())
		return secretList.Items
	}

	Context("when no pull secrets are configured", func() {
		It("should not create any secrets", func() {
			Expect(cli.Create(ctx, installation)).NotTo(HaveOccurred())
			Expect(cli.Create(ctx, istioCR)).NotTo(HaveOccurred())
			createWaypointGateway("waypoint", "user-ns")

			_, err := doReconcile()
			Expect(err).ShouldNot(HaveOccurred())

			secrets := listTrackedSecrets()
			Expect(secrets).To(BeEmpty())
		})
	})

	Context("when pull secrets are configured", func() {
		BeforeEach(func() {
			createPullSecret("my-pull-secret")
			installation.Spec.ImagePullSecrets = []corev1.LocalObjectReference{
				{Name: "my-pull-secret"},
			}
			Expect(cli.Create(ctx, installation)).NotTo(HaveOccurred())
			Expect(cli.Create(ctx, istioCR)).NotTo(HaveOccurred())
		})

		It("should copy pull secrets to waypoint gateway namespace", func() {
			createWaypointGateway("waypoint", "user-ns")

			_, err := doReconcile()
			Expect(err).ShouldNot(HaveOccurred())

			secrets := listTrackedSecrets()
			Expect(secrets).To(HaveLen(1))
			Expect(secrets[0].Namespace).To(Equal("user-ns"))
			Expect(secrets[0].Name).To(Equal("my-pull-secret"))
			Expect(secrets[0].Labels[WaypointPullSecretLabel]).To(Equal("true"))
		})

		It("should copy pull secrets only once for multiple gateways in same namespace", func() {
			createWaypointGateway("waypoint-1", "user-ns")
			createWaypointGateway("waypoint-2", "user-ns")

			_, err := doReconcile()
			Expect(err).ShouldNot(HaveOccurred())

			secrets := listTrackedSecrets()
			Expect(secrets).To(HaveLen(1))
			Expect(secrets[0].Namespace).To(Equal("user-ns"))
		})

		It("should copy pull secrets to all namespaces with waypoint gateways", func() {
			createWaypointGateway("waypoint-a", "ns-a")
			createWaypointGateway("waypoint-b", "ns-b")

			_, err := doReconcile()
			Expect(err).ShouldNot(HaveOccurred())

			secrets := listTrackedSecrets()
			Expect(secrets).To(HaveLen(2))

			namespaces := map[string]bool{}
			for _, s := range secrets {
				namespaces[s.Namespace] = true
			}
			Expect(namespaces).To(HaveKey("ns-a"))
			Expect(namespaces).To(HaveKey("ns-b"))
		})

		It("should clean up stale secrets when gateway is deleted", func() {
			createWaypointGateway("waypoint", "user-ns")

			_, err := doReconcile()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(listTrackedSecrets()).To(HaveLen(1))

			// Delete the gateway.
			gw := &gapi.Gateway{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: "waypoint", Namespace: "user-ns"}, gw)).NotTo(HaveOccurred())
			Expect(cli.Delete(ctx, gw)).NotTo(HaveOccurred())

			// Reconcile again.
			_, err = doReconcile()
			Expect(err).ShouldNot(HaveOccurred())

			// Secrets should be cleaned up.
			Expect(listTrackedSecrets()).To(BeEmpty())
		})

		It("should not take action for non-matching gatewayClassName", func() {
			createNonWaypointGateway("other-gateway", "user-ns")

			_, err := doReconcile()
			Expect(err).ShouldNot(HaveOccurred())

			secrets := listTrackedSecrets()
			Expect(secrets).To(BeEmpty())
		})

		It("should clean up old secret when pull secret is renamed", func() {
			createWaypointGateway("waypoint", "user-ns")

			_, err := doReconcile()
			Expect(err).ShouldNot(HaveOccurred())

			secrets := listTrackedSecrets()
			Expect(secrets).To(HaveLen(1))
			Expect(secrets[0].Name).To(Equal("my-pull-secret"))

			// Change imagePullSecrets from my-pull-secret to new-pull-secret.
			createPullSecret("new-pull-secret")
			inst := &operatorv1.Installation{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: "default"}, inst)).NotTo(HaveOccurred())
			inst.Spec.ImagePullSecrets = []corev1.LocalObjectReference{
				{Name: "new-pull-secret"},
			}
			Expect(cli.Update(ctx, inst)).NotTo(HaveOccurred())

			_, err = doReconcile()
			Expect(err).ShouldNot(HaveOccurred())

			secrets = listTrackedSecrets()
			Expect(secrets).To(HaveLen(1))
			Expect(secrets[0].Name).To(Equal("new-pull-secret"))
			Expect(secrets[0].Namespace).To(Equal("user-ns"))
		})

		It("should copy multiple pull secrets to waypoint namespace", func() {
			createPullSecret("second-pull-secret")
			inst := &operatorv1.Installation{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: "default"}, inst)).NotTo(HaveOccurred())
			inst.Spec.ImagePullSecrets = []corev1.LocalObjectReference{
				{Name: "my-pull-secret"},
				{Name: "second-pull-secret"},
			}
			Expect(cli.Update(ctx, inst)).NotTo(HaveOccurred())

			createWaypointGateway("waypoint", "user-ns")

			_, err := doReconcile()
			Expect(err).ShouldNot(HaveOccurred())

			secrets := listTrackedSecrets()
			Expect(secrets).To(HaveLen(2))

			names := map[string]bool{}
			for _, s := range secrets {
				names[s.Name] = true
				Expect(s.Namespace).To(Equal("user-ns"))
			}
			Expect(names).To(HaveKey("my-pull-secret"))
			Expect(names).To(HaveKey("second-pull-secret"))
		})

		It("should not copy secrets to the operator namespace", func() {
			createWaypointGateway("waypoint", common.OperatorNamespace())

			_, err := doReconcile()
			Expect(err).ShouldNot(HaveOccurred())

			// Pull secrets already exist in the operator namespace; the controller
			// should skip it to avoid overwriting source secrets with labeled copies.
			secrets := listTrackedSecrets()
			Expect(secrets).To(BeEmpty())
		})
	})

	Context("when Istio CR is deleted", func() {
		It("should clean up all copied secrets", func() {
			createPullSecret("my-pull-secret")
			installation.Spec.ImagePullSecrets = []corev1.LocalObjectReference{
				{Name: "my-pull-secret"},
			}
			Expect(cli.Create(ctx, installation)).NotTo(HaveOccurred())
			Expect(cli.Create(ctx, istioCR)).NotTo(HaveOccurred())
			createWaypointGateway("waypoint", "user-ns")

			_, err := doReconcile()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(listTrackedSecrets()).To(HaveLen(1))

			// Delete the Istio CR.
			Expect(cli.Delete(ctx, istioCR)).NotTo(HaveOccurred())

			// Reconcile again.
			_, err = doReconcile()
			Expect(err).ShouldNot(HaveOccurred())

			// All secrets should be cleaned up.
			Expect(listTrackedSecrets()).To(BeEmpty())
		})
	})

	Context("when Installation resource is missing", func() {
		It("should return gracefully without error", func() {
			Expect(cli.Create(ctx, istioCR)).NotTo(HaveOccurred())

			_, err := doReconcile()
			Expect(err).ShouldNot(HaveOccurred())
		})
	})

	Context("when Gateway watch is not yet ready", func() {
		It("should skip Gateway listing and not create secrets", func() {
			r.gatewayWatchReady = &utils.ReadyFlag{}

			createPullSecret("my-pull-secret")
			installation.Spec.ImagePullSecrets = []corev1.LocalObjectReference{
				{Name: "my-pull-secret"},
			}
			Expect(cli.Create(ctx, installation)).NotTo(HaveOccurred())
			Expect(cli.Create(ctx, istioCR)).NotTo(HaveOccurred())
			createWaypointGateway("waypoint", "user-ns")

			_, err := doReconcile()
			Expect(err).ShouldNot(HaveOccurred())

			secrets := listTrackedSecrets()
			Expect(secrets).To(BeEmpty())
		})
	})
})
