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

package whisker

import (
	"context"

	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/types"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/stretchr/testify/mock"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/extensions"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/tls"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/render/whisker"
	admregv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

var _ = Describe("whisker controller tests", func() {
	var (
		cli                   client.Client
		scheme                *runtime.Scheme
		ctx                   context.Context
		mockStatus            *status.MockStatus
		installation          *operatorv1.Installation
		certificateManagement *operatorv1.CertificateManagement
	)

	BeforeEach(func() {
		// Set up the scheme
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).ShouldNot(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(admregv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(networkingv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())

		ctx = context.Background()
		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

		// Create a CertificateManagement instance for tests that need it.
		ca, err := tls.MakeCA(rmeta.DefaultOperatorCASignerName())
		Expect(err).NotTo(HaveOccurred())
		cert, _, _ := ca.Config.GetPEMBytes() // create a valid pem block
		certificateManagement = &operatorv1.CertificateManagement{CACert: cert}

		replicas := int32(2)
		installation = &operatorv1.Installation{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "default",
				Generation: 2,
			},
			Status: operatorv1.InstallationStatus{
				Variant: operatorv1.CalicoEnterprise,
			},
			Spec: operatorv1.InstallationSpec{
				ControlPlaneReplicas: &replicas,
				Variant:              operatorv1.Calico,
				Registry:             "some.registry.org/",
			},
		}
		installation.Status.Computed = installation.Spec.DeepCopy()
		installation.Spec.Variant = ""

		// Apply prerequisites for the basic reconcile to succeed.
		certificateManager, err := certificatemanager.Create(cli, nil, "cluster.local", common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())
		Expect(cli.Create(context.Background(), certificateManager.KeyPair().Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
		Expect(cli.Create(ctx, &operatorv1.APIServer{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
		})).ToNot(HaveOccurred())

		Expect(cli.Create(ctx, &operatorv1.Goldmane{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
		})).ToNot(HaveOccurred())

		Expect(cli.Create(ctx, &operatorv1.Whisker{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
		})).ToNot(HaveOccurred())

		// Set up a mock status
		mockStatus = &status.MockStatus{}
		mockStatus.On("SetWarning", mock.Anything, mock.Anything).Return().Maybe()
		mockStatus.On("ClearWarning", mock.Anything).Return().Maybe()
		mockStatus.On("AddDaemonsets", mock.Anything).Return()
		mockStatus.On("AddDeployments", mock.Anything).Return()
		mockStatus.On("AddStatefulSets", mock.Anything).Return()
		mockStatus.On("AddCronJobs", mock.Anything)
		mockStatus.On("IsAvailable").Return(true)
		mockStatus.On("OnCRFound").Return()
		mockStatus.On("ClearDegraded")
		mockStatus.On("AddCertificateSigningRequests", mock.Anything)
		mockStatus.On("RemoveCertificateSigningRequests", mock.Anything)
		mockStatus.On("ReadyToMonitor")
		mockStatus.On("SetMetaData", mock.Anything).Return()
		mockStatus.On("SetDegraded", operatorv1.ResourceReadError, mock.Anything, mock.Anything, mock.Anything).Return().Maybe()
		mockStatus.On("SetDegraded", operatorv1.ResourceNotReady, mock.Anything, mock.Anything, mock.Anything).Return().Maybe()
	})

	Context("verify reconciliation", func() {
		It("should use builtin images", func() {
			installation.Status.Computed.CertificateManagement = certificateManagement
			Expect(cli.Create(ctx, installation)).To(BeNil())
			reconciler := Reconciler{
				cli:      cli,
				scheme:   scheme,
				provider: operatorv1.ProviderNone,
				status:   mockStatus,
				ext:      extensions.Extensions{}.Whisker(),
			}
			_, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: "default", Namespace: "calico-system"}})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(cli.Get(ctx, types.NamespacedName{Name: installation.Name}, installation)).ShouldNot(HaveOccurred())
			_ = installation
		})

		It("should create the whisker TLS key pairs", func() {
			Expect(cli.Create(ctx, installation)).To(BeNil())
			reconciler := Reconciler{
				cli:      cli,
				scheme:   scheme,
				provider: operatorv1.ProviderNone,
				status:   mockStatus,
				ext:      extensions.Extensions{}.Whisker(),
			}
			_, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: "default", Namespace: "calico-system"}})
			Expect(err).ShouldNot(HaveOccurred())

			for _, name := range []string{whisker.WhiskerKeyPairSecret, whisker.WhiskerBackendKeyPairSecret} {
				secret := &corev1.Secret{}
				Expect(cli.Get(ctx, types.NamespacedName{Name: name, Namespace: common.OperatorNamespace()}, secret)).ShouldNot(HaveOccurred())
				Expect(secret.Data).To(HaveKey("tls.crt"))
				Expect(secret.Data).To(HaveKey("tls.key"))
			}
		})
	})
})
