// Copyright (c) 2023-2026 Tigera, Inc. All rights reserved.

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

package secrets

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	admissionv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/projectcalico/calico/operator/pkg/apis"
	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/components"
	ctrlrfake "github.com/projectcalico/calico/operator/pkg/ctrlruntime/client/fake"
	"github.com/projectcalico/calico/operator/pkg/dns"
	"github.com/projectcalico/calico/operator/pkg/tls/certificatemanagement"
)

func NewClusterCAControllerWithShims(
	cli client.Client,
	scheme *runtime.Scheme,
	clusterDomain string,
) (*ClusterCAController, error) {
	r := &ClusterCAController{
		client:        cli,
		scheme:        scheme,
		clusterDomain: clusterDomain,
		log:           logf.Log.WithName("controller_tenant_secrets"),
	}
	return r, nil
}

var _ = Describe("ClusterCA controller", func() {
	var (
		cli    client.Client
		scheme *runtime.Scheme
		ctx    context.Context
		r      *ClusterCAController
	)

	BeforeEach(func() {
		// Any test-specific preparation should be done in subsequen BeforeEach blocks in the Contexts below.
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).ShouldNot(HaveOccurred())
		Expect(storagev1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(batchv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(admissionv1beta1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		ctx = context.Background()
		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

		// Create a basic Installation.
		install := operatorv1.Installation{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
			},
			Status: operatorv1.InstallationStatus{},
			Spec: operatorv1.InstallationSpec{
				Variant: operatorv1.Calico,
			},
		}
		install.Status.Computed = install.Spec.DeepCopy()
		install.Spec.Variant = ""
		Expect(cli.Create(ctx, &install)).ShouldNot(HaveOccurred())

		var err error
		r, err = NewClusterCAControllerWithShims(cli, scheme, dns.DefaultClusterDomain)
		Expect(err).ShouldNot(HaveOccurred())
	})

	It("should provision the Cluster CA", func() {
		// Run the reconciler.
		_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default", Namespace: "tigera-operator"}})
		Expect(err).ShouldNot(HaveOccurred())

		// Query for the Cluster CA which should have been created.
		caSecret := &corev1.Secret{}
		Expect(cli.Get(ctx, types.NamespacedName{Name: certificatemanagement.CASecretName, Namespace: common.OperatorNamespace()}, caSecret)).ShouldNot(HaveOccurred())
		Expect(caSecret.Data).Should(HaveKey("tls.crt"))
	})

	It("should Reconcile with ImageSet", func() {
		Expect(cli.Create(ctx, &operatorv1.ImageSet{
			ObjectMeta: metav1.ObjectMeta{
				Name: fmt.Sprintf("calico-%s", components.CalicoRelease),
			},
			Spec: operatorv1.ImageSetSpec{
				Images: []operatorv1.Image{
					{
						Image:  fmt.Sprintf("%s%s", components.CalicoImagePath, components.ComponentCalico.Image),
						Digest: "sha256:xxxxxxxxx",
					}, {
						Image:  fmt.Sprintf("%s%s", components.TigeraImagePath, components.ComponentTigeraCalico.Image),
						Digest: "sha256:xxxxxxxxx",
					},
				},
			},
		})).ShouldNot(HaveOccurred())
		// Run the reconciler.
		_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default", Namespace: "tigera-operator"}})
		Expect(err).ShouldNot(HaveOccurred())

		// Query for the Cluster CA which should have been created.
		caSecret := &corev1.Secret{}
		Expect(cli.Get(ctx, types.NamespacedName{Name: certificatemanagement.CASecretName, Namespace: common.OperatorNamespace()}, caSecret)).ShouldNot(HaveOccurred())
		Expect(caSecret.Data).Should(HaveKey("tls.crt"))
	})

	// The broken Calico ImageSet fails to load if the reconciler reads the spec
	// instead of the status.
	It("should Reconcile from the computed spec", func() {
		install := operatorv1.Installation{}
		Expect(cli.Get(ctx, types.NamespacedName{Name: "default"}, &install)).ShouldNot(HaveOccurred())
		install.Status.Computed = install.Spec.DeepCopy()
		install.Status.Computed.Variant = operatorv1.CalicoEnterprise
		Expect(cli.Status().Update(ctx, &install)).ShouldNot(HaveOccurred())
		Expect(cli.Create(ctx, &operatorv1.ImageSet{
			ObjectMeta: metav1.ObjectMeta{
				Name: "calico-brokenver",
			},
			Spec: operatorv1.ImageSetSpec{
				Images: []operatorv1.Image{
					{
						Image:  fmt.Sprintf("%s%s", components.CalicoImagePath, components.ComponentCalico.Image),
						Digest: "sha256:xxxxxxxxx",
					}, {
						Image:  fmt.Sprintf("%s%s", components.TigeraImagePath, components.ComponentTigeraCalico.Image),
						Digest: "sha256:xxxxxxxxx",
					},
				},
			},
		})).ShouldNot(HaveOccurred())
		// Run the reconciler.
		_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default", Namespace: "tigera-operator"}})
		Expect(err).ShouldNot(HaveOccurred())

		// Query for the Cluster CA which should have been created.
		caSecret := &corev1.Secret{}
		Expect(cli.Get(ctx, types.NamespacedName{Name: certificatemanagement.CASecretName, Namespace: common.OperatorNamespace()}, caSecret)).ShouldNot(HaveOccurred())
		Expect(caSecret.Data).Should(HaveKey("tls.crt"))
	})
})
