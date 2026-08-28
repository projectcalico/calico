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

package goldmane

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/stretchr/testify/mock"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/status"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/extensions"
	"github.com/tigera/operator/pkg/render"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/goldmane"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

var _ = Describe("Goldmane controller tests", func() {
	var (
		cli        client.Client
		scheme     *runtime.Scheme
		ctx        context.Context
		mockStatus *status.MockStatus
		reconciler Reconciler
	)

	// reconcileRequest reconciles the default Goldmane CR.
	reconcileRequest := func() (reconcile.Result, error) {
		return reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default"}})
	}

	// bundleData returns the rendered goldmane trusted bundle ConfigMap data, or "" if it was not created.
	bundleData := func() string {
		cm := &corev1.ConfigMap{}
		name := certificatemanagement.TrustedBundleName(goldmane.GoldmaneDeploymentName, false)
		err := cli.Get(ctx, types.NamespacedName{Name: name, Namespace: goldmane.GoldmaneNamespace}, cm)
		if err != nil {
			return ""
		}
		return cm.Data[certificatemanagement.TrustedCertConfigMapKeyName]
	}

	// setDegradedCalledWith reports whether SetDegraded was invoked with the given reason.
	setDegradedCalledWith := func(reason operatorv1.TigeraStatusReason) bool {
		for _, c := range mockStatus.Calls {
			if c.Method == "SetDegraded" && len(c.Arguments) > 0 && c.Arguments[0] == reason {
				return true
			}
		}
		return false
	}

	BeforeEach(func() {
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).ShouldNot(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())

		ctx = context.Background()
		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

		// Prerequisites for a successful reconcile.
		Expect(cli.Create(ctx, &operatorv1.Goldmane{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
		})).ToNot(HaveOccurred())
		Expect(cli.Create(ctx, &operatorv1.Installation{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Status: operatorv1.InstallationStatus{
				Variant:  operatorv1.Calico,
				Computed: &operatorv1.InstallationSpec{Variant: operatorv1.Calico},
			},
			Spec: operatorv1.InstallationSpec{Variant: operatorv1.Calico},
		})).ToNot(HaveOccurred())

		// Persist the operator root CA so the trusted bundle can be signed.
		certificateManager, err := certificatemanager.Create(cli, nil, "cluster.local", common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())
		Expect(cli.Create(ctx, certificateManager.KeyPair().Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

		mockStatus = &status.MockStatus{}
		mockStatus.On("SetWarning", mock.Anything, mock.Anything).Return().Maybe()
		mockStatus.On("ClearWarning", mock.Anything).Return().Maybe()
		mockStatus.On("OnCRFound").Return()
		mockStatus.On("OnCRNotFound").Return().Maybe()
		mockStatus.On("SetMetaData", mock.Anything).Return()
		mockStatus.On("ReadyToMonitor").Return()
		mockStatus.On("ClearDegraded").Return()
		mockStatus.On("AddDeployments", mock.Anything).Return().Maybe()
		mockStatus.On("AddDaemonsets", mock.Anything).Return().Maybe()
		mockStatus.On("AddStatefulSets", mock.Anything).Return().Maybe()
		mockStatus.On("AddCronJobs", mock.Anything).Return().Maybe()
		mockStatus.On("IsAvailable").Return(true).Maybe()
		mockStatus.On("AddCertificateSigningRequests", mock.Anything).Return().Maybe()
		mockStatus.On("RemoveCertificateSigningRequests", mock.Anything).Return().Maybe()
		mockStatus.On("SetDegraded", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return().Maybe()

		reconciler = Reconciler{
			cli:           cli,
			scheme:        scheme,
			provider:      operatorv1.ProviderNone,
			status:        mockStatus,
			clusterDomain: "cluster.local",
			ext:           extensions.Extensions{}.Goldmane(),
		}
	})

	// createLinseedPublicCert creates a Voltron Linseed public certificate secret under the given name,
	// mimicking the cert that the management cluster (e.g. Calico Cloud) delivers to a managed cluster. It is
	// signed by a CA distinct from the local operator signer, so it must be added to the trusted bundle.
	createLinseedPublicCert := func(secretName string) {
		Expect(cli.Create(ctx, rtest.CreateCertSecret(secretName, common.OperatorNamespace(), secretName))).NotTo(HaveOccurred())
	}

	Context("connected to a management cluster", func() {
		BeforeEach(func() {
			Expect(cli.Create(ctx, &operatorv1.ManagementClusterConnection{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			})).ToNot(HaveOccurred())
		})

		It("trusts the legacy tigera-voltron-linseed-certs-public secret", func() {
			createLinseedPublicCert(render.LegacyVoltronLinseedPublicCert)

			_, err := reconcileRequest()
			Expect(err).ShouldNot(HaveOccurred())

			// The cloud signer must be present in the trusted bundle so the flow emitter can verify Guardian.
			Expect(bundleData()).To(ContainSubstring(render.LegacyVoltronLinseedPublicCert))
		})

		It("trusts the current calico-voltron-linseed-certs-public secret", func() {
			createLinseedPublicCert(render.VoltronLinseedPublicCert)

			_, err := reconcileRequest()
			Expect(err).ShouldNot(HaveOccurred())

			Expect(bundleData()).To(ContainSubstring(render.VoltronLinseedPublicCert))
		})

		It("degrades when no Linseed public certificate is present", func() {
			result, err := reconcileRequest()

			// We should degrade and requeue rather than silently ship a bundle missing the cloud signer.
			Expect(err).ShouldNot(HaveOccurred())
			Expect(result).To(Equal(reconcile.Result{}))
			Expect(setDegradedCalledWith(operatorv1.ResourceNotReady)).To(BeTrue())

			// The bundle should not have been rendered, since we returned early.
			Expect(bundleData()).To(BeEmpty())
		})
	})

	Context("standalone cluster (no management cluster connection)", func() {
		It("does not require the Linseed public certificate", func() {
			// Even if a cloud cert exists, a standalone goldmane does not emit flows and should not degrade on it.
			_, err := reconcileRequest()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(setDegradedCalledWith(operatorv1.ResourceNotReady)).To(BeFalse())
			Expect(bundleData()).ToNot(ContainSubstring(render.LegacyVoltronLinseedPublicCert))
		})
	})
})
