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

package managedcluster

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	admissionv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/utils"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
)

func NewReconcilerWithShims(
	cli client.Client,
	scheme *runtime.Scheme,
	provider operatorv1.Provider,
	clusterDomain string,
) (*LogStorageManagedClusterController, error) {
	opts := options.ControllerOptions{
		DetectedProvider: provider,
		ClusterDomain:    clusterDomain,
		ShutdownContext:  context.TODO(),
		Variant:          operatorv1.CalicoEnterprise,
	}

	r := &LogStorageManagedClusterController{
		client:        cli,
		scheme:        scheme,
		clusterDomain: opts.ClusterDomain,
		provider:      opts.DetectedProvider,
	}
	return r, nil
}

var _ = Describe("LogStorageManagedCluster controller", func() {
	var (
		cli     client.Client
		scheme  *runtime.Scheme
		ctx     context.Context
		install *operatorv1.Installation
	)

	BeforeEach(func() {
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).ShouldNot(HaveOccurred())
		Expect(storagev1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(batchv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(admissionv1beta1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())

		ctx = context.Background()
		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

		var replicas int32 = 2
		install = &operatorv1.Installation{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
			},
			Status: operatorv1.InstallationStatus{
				Variant: operatorv1.CalicoEnterprise,
			},
			Spec: operatorv1.InstallationSpec{
				ControlPlaneReplicas: &replicas,
				Variant:              operatorv1.CalicoEnterprise,
			},
		}
		install.Status.Computed = &install.Spec
		Expect(cli.Create(ctx, install)).ShouldNot(HaveOccurred())
	})

	Context("Managed Cluster", func() {
		Context("LogStorage is nil", func() {
			BeforeEach(func() {
				Expect(cli.Create(ctx, &operatorv1.ManagementClusterConnection{ObjectMeta: metav1.ObjectMeta{Name: utils.DefaultEnterpriseInstanceKey.Name}})).NotTo(HaveOccurred())
			})

			Context("LogStorage exists", func() {
				BeforeEach(func() {
					Expect(cli.Create(ctx, &operatorv1.LogStorage{
						ObjectMeta: metav1.ObjectMeta{
							Name: "tigera-secure",
						},
					})).NotTo(HaveOccurred())
				})

				It("returns an error if the LogStorage resource exists", func() {
					r, err := NewReconcilerWithShims(cli, scheme, operatorv1.ProviderNone, "cluster.local")
					Expect(err).ShouldNot(HaveOccurred())
					_, err = r.Reconcile(ctx, reconcile.Request{})
					Expect(err).Should(HaveOccurred())
				})
			})
		})
	})
})
