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

package clusterconnection_test

import (
	"context"
	"fmt"
	"reflect"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/extensions"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

var _ = Describe("clusterconnection enterprise controller extension", func() {
	var cli client.Client

	// controllerInputs builds a Inputs selecting the enterprise
	// clusterconnection hook against the given client.
	controllerInputs := func() controller.Inputs {
		cm, err := certificatemanager.Create(cli, nil, "", common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())
		return controller.Inputs{
			RenderInputs: render.Inputs{
				Installation:  &operatorv1.InstallationSpec{Variant: operatorv1.CalicoEnterprise},
				TrustedBundle: cm.CreateTrustedBundle(),
			},
			Client:             cli,
			CertificateManager: cm,
		}
	}

	clusterInformation := func() *v3.ClusterInformation {
		return &v3.ClusterInformation{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec:       v3.ClusterInformationSpec{CNXVersion: "v3.99.0", CalicoVersion: "v3.99.0-calico"},
		}
	}

	newClient := func(objs ...client.Object) client.Client {
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		return ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(objs...).Build()
	}

	// failingGetClient fails every read of an object of the same type as fail.
	failingGetClient := func(fail client.Object, readErr error) client.Client {
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		return ctrlrfake.DefaultFakeClientBuilder(scheme).WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if reflect.TypeOf(obj) == reflect.TypeOf(fail) {
					return readErr
				}
				return c.Get(ctx, key, obj, opts...)
			},
		}).Build()
	}

	Describe("configuration", func() {
		It("rejects a cluster that is both a management and a managed cluster", func() {
			cli = newClient(&operatorv1.ManagementCluster{ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}})
			_, _, err := ext.ClusterConnection().ExtendInputs(ctx, controllerInputs())
			reason, ok := extensions.DegradedReason(err)
			Expect(ok).To(BeTrue())
			Expect(reason).To(Equal(operatorv1.ResourceValidationError))
			Expect(err.Error()).To(ContainSubstring("not supported"))
		})

		It("degrades with a read error when the ManagementCluster cannot be read", func() {
			readErr := fmt.Errorf("the API server is having a bad day")
			cli = failingGetClient(&operatorv1.ManagementCluster{}, readErr)

			_, _, err := ext.ClusterConnection().ExtendInputs(ctx, controllerInputs())
			Expect(err).To(MatchError(readErr))
			reason, ok := extensions.DegradedReason(err)
			Expect(ok).To(BeTrue())
			Expect(reason).To(Equal(operatorv1.ResourceReadError))
		})

		It("accepts impersonation and defaults it to empty lists", func() {
			cr := &operatorv1.ManagementClusterConnection{}
			Expect(ext.ClusterConnection().ValidateAndDefault(cr)).NotTo(HaveOccurred())
			Expect(cr.Spec.Impersonation).To(Equal(&operatorv1.Impersonation{
				Users:           []string{},
				Groups:          []string{},
				ServiceAccounts: []string{},
			}))
		})

		It("leaves impersonation the user set alone", func() {
			cr := &operatorv1.ManagementClusterConnection{
				Spec: operatorv1.ManagementClusterConnectionSpec{
					Impersonation: &operatorv1.Impersonation{Users: []string{"jane"}},
				},
			}
			Expect(ext.ClusterConnection().ValidateAndDefault(cr)).NotTo(HaveOccurred())
			Expect(cr.Spec.Impersonation.Users).To(Equal([]string{"jane"}))
		})

		It("accepts a public CA, which enterprise guardian can trust", func() {
			cr := &operatorv1.ManagementClusterConnection{
				Spec: operatorv1.ManagementClusterConnectionSpec{
					TLS: &operatorv1.ManagementClusterTLS{CA: operatorv1.CATypePublic},
				},
			}
			Expect(ext.ClusterConnection().ValidateAndDefault(cr)).NotTo(HaveOccurred())
		})
	})

	Describe("ExtendInputs", func() {
		It("reports the managed cluster CNX version", func() {
			cli = newClient(clusterInformation())
			eci, managed, err := ext.ClusterConnection().ExtendInputs(ctx, controllerInputs())
			ri := eci.RenderInputs
			Expect(err).NotTo(HaveOccurred())
			Expect(managed).To(BeEmpty())

			data, ok := render.GuardianRenderDataFromInputs(ri)
			Expect(ok).To(BeTrue())
			Expect(data.Version).To(Equal("v3.99.0"))
			Expect(data.IncludeEgressNetworkPolicy).To(BeFalse())
		})

		It("enables the egress network policy when the license has the feature", func() {
			license := &v3.LicenseKey{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Status:     v3.LicenseKeyStatus{Features: []string{common.EgressAccessControlFeature}},
			}
			cli = newClient(clusterInformation(), license)
			eci, _, err := ext.ClusterConnection().ExtendInputs(ctx, controllerInputs())
			ri := eci.RenderInputs
			Expect(err).NotTo(HaveOccurred())

			data, ok := render.GuardianRenderDataFromInputs(ri)
			Expect(ok).To(BeTrue())
			Expect(data.IncludeEgressNetworkPolicy).To(BeTrue())
		})

		It("adds the enterprise certificates guardian must trust", func() {
			var trusted []client.Object
			for _, name := range []string{render.PacketCaptureServerCert, monitor.PrometheusServerTLSSecretName} {
				secret, err := certificatemanagement.CreateSelfSignedSecret(name, common.OperatorNamespace(), name, nil)
				Expect(err).NotTo(HaveOccurred())
				trusted = append(trusted, secret)
			}
			cli = newClient(append(trusted, clusterInformation())...)

			eci, _, err := ext.ClusterConnection().ExtendInputs(ctx, controllerInputs())
			Expect(err).NotTo(HaveOccurred())
			Expect(eci.RenderInputs.TrustedBundle.HashAnnotations()).To(HaveKey(ContainSubstring(render.PacketCaptureServerCert)))
			Expect(eci.RenderInputs.TrustedBundle.HashAnnotations()).To(HaveKey(ContainSubstring(monitor.PrometheusServerTLSSecretName)))
		})

		It("errors when ClusterInformation is missing", func() {
			cli = newClient()
			_, _, err := ext.ClusterConnection().ExtendInputs(ctx, controllerInputs())
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("ClusterInformation"))
		})
	})
})
