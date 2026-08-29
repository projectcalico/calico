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

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gapi "sigs.k8s.io/gateway-api/apis/v1"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/apis"
	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/controller/certificatemanager"
	"github.com/projectcalico/calico/operator/pkg/controller/utils"
	ctrlrfake "github.com/projectcalico/calico/operator/pkg/ctrlruntime/client/fake"
	"github.com/projectcalico/calico/operator/pkg/render"
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
		installation.Status.Computed = &installation.Spec

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

	istioOwnerRef := func(obj client.Object) *metav1.OwnerReference {
		for _, ref := range obj.GetOwnerReferences() {
			if ref.Kind == "Istio" {
				return &ref
			}
		}
		return nil
	}

	// The objects this controller creates are identified by their Istio owner reference,
	// the same way Kubernetes garbage collection finds them. The source pull secrets and
	// the certificate manager secret in the operator namespace carry no owner reference,
	// so they are excluded.
	listOwnedSecrets := func() []corev1.Secret {
		secretList := &corev1.SecretList{}
		Expect(cli.List(ctx, secretList)).NotTo(HaveOccurred())
		var owned []corev1.Secret
		for _, s := range secretList.Items {
			if istioOwnerRef(&s) != nil {
				owned = append(owned, s)
			}
		}
		return owned
	}

	listOwnedRoleBindings := func() []rbacv1.RoleBinding {
		rbList := &rbacv1.RoleBindingList{}
		Expect(cli.List(ctx, rbList)).NotTo(HaveOccurred())
		var owned []rbacv1.RoleBinding
		for _, rb := range rbList.Items {
			if istioOwnerRef(&rb) != nil {
				owned = append(owned, rb)
			}
		}
		return owned
	}

	Context("when no pull secrets are configured", func() {
		It("should not create any secrets or role bindings", func() {
			Expect(cli.Create(ctx, installation)).NotTo(HaveOccurred())
			Expect(cli.Create(ctx, istioCR)).NotTo(HaveOccurred())
			createWaypointGateway("waypoint", "user-ns")

			_, err := doReconcile()
			Expect(err).ShouldNot(HaveOccurred())

			Expect(listOwnedSecrets()).To(BeEmpty())
			Expect(listOwnedRoleBindings()).To(BeEmpty())
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

			secrets := listOwnedSecrets()
			Expect(secrets).To(HaveLen(1))
			Expect(secrets[0].Namespace).To(Equal("user-ns"))
			Expect(secrets[0].Name).To(Equal("my-pull-secret"))
			// The MultipleOwnersLabel is a directive to the component handler and must not persist.
			Expect(secrets[0].Labels).NotTo(HaveKey(common.MultipleOwnersLabel))
		})

		It("should create a tigera-operator-secrets RoleBinding in the waypoint namespace", func() {
			createWaypointGateway("waypoint", "user-ns")

			_, err := doReconcile()
			Expect(err).ShouldNot(HaveOccurred())

			rbs := listOwnedRoleBindings()
			Expect(rbs).To(HaveLen(1))
			rb := rbs[0]
			Expect(rb.Namespace).To(Equal("user-ns"))
			Expect(rb.Name).To(Equal(render.TigeraOperatorSecrets))
			Expect(rb.RoleRef.Kind).To(Equal("ClusterRole"))
			Expect(rb.RoleRef.Name).To(Equal(render.TigeraOperatorSecrets))
			Expect(rb.Subjects).To(ConsistOf(rbacv1.Subject{
				Kind:      "ServiceAccount",
				Name:      common.OperatorServiceAccount(),
				Namespace: common.OperatorNamespace(),
			}))
			// The MultipleOwnersLabel is a directive to the component handler and must not persist.
			Expect(rb.Labels).NotTo(HaveKey(common.MultipleOwnersLabel))
		})

		It("should set an owner reference to the Istio CR on copied secrets and role bindings", func() {
			createWaypointGateway("waypoint", "user-ns")

			_, err := doReconcile()
			Expect(err).ShouldNot(HaveOccurred())

			secrets := listOwnedSecrets()
			Expect(secrets).To(HaveLen(1))
			ref := istioOwnerRef(&secrets[0])
			Expect(ref).NotTo(BeNil())
			Expect(ref.Name).To(Equal("default"))
			Expect(ref.APIVersion).To(Equal("operator.tigera.io/v1"))

			rbs := listOwnedRoleBindings()
			Expect(rbs).To(HaveLen(1))
			ref = istioOwnerRef(&rbs[0])
			Expect(ref).NotTo(BeNil())
			Expect(ref.Name).To(Equal("default"))
			Expect(ref.APIVersion).To(Equal("operator.tigera.io/v1"))
		})

		It("should update copied secrets when the base pull secret changes", func() {
			createWaypointGateway("waypoint", "user-ns")

			_, err := doReconcile()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(listOwnedSecrets()).To(HaveLen(1))

			// Rotate the base pull secret in the operator namespace.
			base := &corev1.Secret{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: "my-pull-secret", Namespace: common.OperatorNamespace()}, base)).NotTo(HaveOccurred())
			newData := []byte(`{"auths":{"registry.example.com":{"auth":"cm90YXRlZDpyb3RhdGVk"}}}`)
			base.Data[".dockerconfigjson"] = newData
			Expect(cli.Update(ctx, base)).NotTo(HaveOccurred())

			_, err = doReconcile()
			Expect(err).ShouldNot(HaveOccurred())

			secrets := listOwnedSecrets()
			Expect(secrets).To(HaveLen(1))
			Expect(secrets[0].Data[".dockerconfigjson"]).To(Equal(newData))
		})

		It("should merge owner references on a RoleBinding shared with an egress gateway", func() {
			// Simulate the egress gateway controller having already created the
			// shared RoleBinding in the namespace, owned by its CR.
			createNamespace("shared-ns")
			rb := render.CreateOperatorSecretsRoleBinding("shared-ns")
			rb.OwnerReferences = []metav1.OwnerReference{
				{
					APIVersion: "operator.tigera.io/v1",
					Kind:       "EgressGateway",
					Name:       "egw",
					UID:        types.UID("egw-uid"),
				},
			}
			Expect(cli.Create(ctx, rb)).NotTo(HaveOccurred())

			createWaypointGateway("waypoint", "shared-ns")

			_, err := doReconcile()
			Expect(err).ShouldNot(HaveOccurred())

			// The Istio owner reference is added alongside the egress gateway's,
			// not in place of it.
			got := &rbacv1.RoleBinding{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: render.TigeraOperatorSecrets, Namespace: "shared-ns"}, got)).NotTo(HaveOccurred())
			kinds := map[string]bool{}
			for _, ref := range got.OwnerReferences {
				kinds[ref.Kind] = true
			}
			Expect(kinds).To(HaveKey("EgressGateway"))
			Expect(kinds).To(HaveKey("Istio"))
		})

		It("should order the RoleBinding ahead of the secret copies", func() {
			// The RoleBinding grants the operator permission to write secrets in
			// the namespace, so it must be created first.
			createWaypointGateway("waypoint", "user-ns")

			objs, err := r.pullSecretResources(ctx, logr.Discard())
			Expect(err).ShouldNot(HaveOccurred())
			Expect(objs).To(HaveLen(2))
			Expect(objs[0]).To(BeAssignableToTypeOf(&rbacv1.RoleBinding{}))
			Expect(objs[1]).To(BeAssignableToTypeOf(&corev1.Secret{}))
		})

		It("should not create resources for a gateway in the legacy gateway namespace", func() {
			// The gateway-API controller's legacy teardown queues tigera-gateway's copies
			// and RoleBinding for deletion whenever no Gateway of a class it owns lives
			// there, so anything created here would be deleted and recreated for as long as
			// both controllers keep reconciling.
			createWaypointGateway("waypoint-legacy-gateway", "tigera-gateway")

			_, err := doReconcile()
			Expect(err).ShouldNot(HaveOccurred())

			Expect(listOwnedSecrets()).To(BeEmpty())
			Expect(listOwnedRoleBindings()).To(BeEmpty())
		})

		It("should copy pull secrets only once for multiple gateways in same namespace", func() {
			createWaypointGateway("waypoint-1", "user-ns")
			createWaypointGateway("waypoint-2", "user-ns")

			_, err := doReconcile()
			Expect(err).ShouldNot(HaveOccurred())

			secrets := listOwnedSecrets()
			Expect(secrets).To(HaveLen(1))
			Expect(secrets[0].Namespace).To(Equal("user-ns"))
		})

		It("should copy pull secrets to all namespaces with waypoint gateways", func() {
			createWaypointGateway("waypoint-a", "ns-a")
			createWaypointGateway("waypoint-b", "ns-b")

			_, err := doReconcile()
			Expect(err).ShouldNot(HaveOccurred())

			secrets := listOwnedSecrets()
			Expect(secrets).To(HaveLen(2))

			namespaces := map[string]bool{}
			for _, s := range secrets {
				namespaces[s.Namespace] = true
			}
			Expect(namespaces).To(HaveKey("ns-a"))
			Expect(namespaces).To(HaveKey("ns-b"))
		})

		It("should not take action for non-matching gatewayClassName", func() {
			createNonWaypointGateway("other-gateway", "user-ns")

			_, err := doReconcile()
			Expect(err).ShouldNot(HaveOccurred())

			secrets := listOwnedSecrets()
			Expect(secrets).To(BeEmpty())
		})

		It("should copy a renamed pull secret, leaving the old copy for the planned cleanup work", func() {
			createWaypointGateway("waypoint", "user-ns")

			_, err := doReconcile()
			Expect(err).ShouldNot(HaveOccurred())

			secrets := listOwnedSecrets()
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
			inst.Status.Computed = inst.Spec.DeepCopy()
			Expect(cli.Status().Update(ctx, inst)).NotTo(HaveOccurred())

			_, err = doReconcile()
			Expect(err).ShouldNot(HaveOccurred())

			// The new copy exists; the old one is stranded until the Istio CR is
			// deleted — the same behaviour the egress gateway has today.
			names := map[string]bool{}
			for _, s := range listOwnedSecrets() {
				Expect(s.Namespace).To(Equal("user-ns"))
				names[s.Name] = true
			}
			Expect(names).To(HaveKey("new-pull-secret"))
			Expect(names).To(HaveKey("my-pull-secret"))
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
			inst.Status.Computed = inst.Spec.DeepCopy()
			Expect(cli.Status().Update(ctx, inst)).NotTo(HaveOccurred())

			createWaypointGateway("waypoint", "user-ns")

			_, err := doReconcile()
			Expect(err).ShouldNot(HaveOccurred())

			secrets := listOwnedSecrets()
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
			// should skip it rather than overwrite the source secrets with copies.
			secrets := listOwnedSecrets()
			Expect(secrets).To(BeEmpty())
		})
	})

	Context("when Istio CR is deleted", func() {
		It("should reconcile without error and leave cleanup to garbage collection", func() {
			createPullSecret("my-pull-secret")
			installation.Spec.ImagePullSecrets = []corev1.LocalObjectReference{
				{Name: "my-pull-secret"},
			}
			Expect(cli.Create(ctx, installation)).NotTo(HaveOccurred())
			Expect(cli.Create(ctx, istioCR)).NotTo(HaveOccurred())
			createWaypointGateway("waypoint", "user-ns")

			_, err := doReconcile()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(listOwnedSecrets()).To(HaveLen(1))
			Expect(listOwnedRoleBindings()).To(HaveLen(1))

			// Delete the Istio CR and reconcile again: the controller takes no
			// action. On a real cluster the copies and RoleBindings are removed
			// by Kubernetes garbage collection via their Istio owner reference,
			// which the fake client does not implement.
			Expect(cli.Delete(ctx, istioCR)).NotTo(HaveOccurred())

			_, err = doReconcile()
			Expect(err).ShouldNot(HaveOccurred())
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

			secrets := listOwnedSecrets()
			Expect(secrets).To(BeEmpty())
		})
	})
})
