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

package installation_test

import (
	"context"
	"fmt"
	"reflect"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/utils"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/enterprise/render/monitor"
	"github.com/tigera/operator/pkg/extensions"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/pkg/render/common/rbacmanagement"
	"github.com/tigera/operator/pkg/render/kubecontrollers"
)

var _ = Describe("installation controller extension", func() {
	It("rejects a zero prometheus reporter port", func() {
		port := 0
		ci := newControllerInputs(operatorv1.CalicoEnterprise)
		ci.RenderInputs.FelixConfiguration = &v3.FelixConfiguration{
			Spec: v3.FelixConfigurationSpec{PrometheusReporterPort: &port},
		}
		_, _, err := ext.Installation().ExtendInputs(ctx, ci)
		reason, ok := extensions.DegradedReason(err)
		Expect(ok).To(BeTrue())
		Expect(reason).To(Equal(operatorv1.InvalidConfigurationError))
	})

	DescribeTable("defaults dnsTrustedServers for providers whose DNS service isn't kube-dns",
		func(provider operatorv1.Provider, expected []string) {
			fc := &v3.FelixConfiguration{}
			install := &operatorv1.InstallationSpec{Variant: operatorv1.CalicoEnterprise, KubernetesProvider: provider}
			updated, err := ext.Installation().DefaultFelixConfiguration(install, fc)
			Expect(err).NotTo(HaveOccurred())
			if expected == nil {
				Expect(updated).To(BeFalse())
				Expect(fc.Spec.DNSTrustedServers).To(BeNil())
				return
			}
			Expect(updated).To(BeTrue())
			Expect(*fc.Spec.DNSTrustedServers).To(ConsistOf(expected))
		},
		Entry("OpenShift", operatorv1.ProviderOpenShift, []string{"k8s-service:openshift-dns/dns-default"}),
		Entry("RKE2", operatorv1.ProviderRKE2, []string{"k8s-service:kube-system/rke2-coredns-rke2-coredns"}),
		Entry("other providers keep the felix default", operatorv1.ProviderNone, nil),
	)

	It("does no felix defaulting when the operator runs as Calico", func() {
		fc := &v3.FelixConfiguration{}
		updated, err := calicoExt.Installation().DefaultFelixConfiguration(&operatorv1.InstallationSpec{Variant: operatorv1.Calico, KubernetesProvider: operatorv1.ProviderOpenShift}, fc)
		Expect(err).NotTo(HaveOccurred())
		Expect(updated).To(BeFalse())
		Expect(fc.Spec.DNSTrustedServers).To(BeNil())
	})

	It("manages the node prometheus and kube-controllers metrics keypairs for the enterprise variant", func() {
		_, managed, err := ext.Installation().ExtendInputs(ctx, newControllerInputs(operatorv1.CalicoEnterprise))
		Expect(err).NotTo(HaveOccurred())
		names := []string{}
		for _, kp := range managed {
			names = append(names, kp.GetName())
		}
		Expect(names).To(ConsistOf(render.NodePrometheusTLSServerSecret, kubecontrollers.KubeControllerPrometheusTLSSecret))
	})

	It("rejects an existing Goldmane CR", func() {
		ci := newControllerInputs(operatorv1.CalicoEnterprise, &operatorv1.Goldmane{
			ObjectMeta: metav1.ObjectMeta{Name: utils.DefaultInstanceKey.Name},
		})

		_, _, err := ext.Installation().ExtendInputs(ctx, ci)
		Expect(err).To(MatchError(ContainSubstring("delete the Goldmane \"default\" resource")))
		reason, ok := extensions.DegradedReason(err)
		Expect(ok).To(BeTrue())
		Expect(reason).To(Equal(operatorv1.ResourceValidationError))

		goldmane, err := utils.GetIfExists[operatorv1.Goldmane](ctx, utils.DefaultInstanceKey, ci.Client)
		Expect(err).NotTo(HaveOccurred())
		Expect(goldmane).NotTo(BeNil())
	})

	It("accepts a Goldmane CR while the installation is still Calico", func() {
		ci := newControllerInputs(operatorv1.Calico, &operatorv1.Goldmane{
			ObjectMeta: metav1.ObjectMeta{Name: utils.DefaultInstanceKey.Name},
		})

		_, _, err := ext.Installation().ExtendInputs(ctx, ci)
		Expect(err).NotTo(HaveOccurred())
	})

	It("is a no-op when the operator runs as Calico", func() {
		_, managed, err := calicoExt.Installation().ExtendInputs(ctx, newControllerInputs(operatorv1.Calico))
		Expect(err).NotTo(HaveOccurred())
		Expect(managed).To(BeEmpty())
	})

	DescribeTable("reports the degraded reason for the read it failed on",
		func(fail failingGet, expected operatorv1.TigeraStatusReason) {
			readErr := fmt.Errorf("the API server is having a bad day")
			ci := newControllerInputsWith(failingGetClient(fail, readErr), operatorv1.CalicoEnterprise)

			_, _, err := ext.Installation().ExtendInputs(ctx, ci)
			Expect(err).To(MatchError(readErr))
			reason, ok := extensions.DegradedReason(err)
			Expect(ok).To(BeTrue())
			Expect(reason).To(Equal(expected))
		},
		Entry("the node prometheus keypair",
			failingGet{obj: &corev1.Secret{}, name: render.NodePrometheusTLSServerSecret}, operatorv1.ResourceCreateError),
		Entry("the kube-controllers metrics keypair",
			failingGet{obj: &corev1.Secret{}, name: kubecontrollers.KubeControllerPrometheusTLSSecret}, operatorv1.ResourceReadError),
		Entry("the LogCollector",
			failingGet{obj: &operatorv1.LogCollector{}}, operatorv1.ResourceReadError),
		Entry("the ManagementClusterConnection",
			failingGet{obj: &operatorv1.ManagementClusterConnection{}}, operatorv1.ResourceReadError),
		Entry("the ManagementCluster",
			failingGet{obj: &operatorv1.ManagementCluster{}}, operatorv1.ResourceReadError),
		Entry("the GatewayAPI",
			failingGet{obj: &operatorv1.GatewayAPI{}}, operatorv1.ResourceReadError),
		Entry("the RBAC management UI ConfigMap",
			failingGet{obj: &corev1.ConfigMap{}, name: rbacmanagement.ConfigMapName}, operatorv1.ResourceReadError),
		Entry("the prometheus client certificate",
			failingGet{obj: &corev1.Secret{}, name: monitor.PrometheusClientTLSSecretName}, operatorv1.CertificateError),
		Entry("the elasticsearch gateway certificate",
			failingGet{obj: &corev1.Secret{}, name: relasticsearch.PublicCertSecret}, operatorv1.CertificateError),
		Entry("the manager internal certificate",
			failingGet{obj: &corev1.Secret{}, name: render.ManagerInternalTLSSecretName}, operatorv1.ResourceReadError),
	)
})

// failingGet names the object read that should fail: any object of the same type as
// obj, narrowed to a single name when one is given.
type failingGet struct {
	obj  client.Object
	name string
}

func (f failingGet) matches(key client.ObjectKey, obj client.Object) bool {
	if reflect.TypeOf(obj) != reflect.TypeOf(f.obj) {
		return false
	}
	return f.name == "" || f.name == key.Name
}

func failingGetClient(fail failingGet, readErr error) client.WithWatch {
	return ctrlrfake.DefaultFakeClientBuilder(installationScheme()).WithInterceptorFuncs(interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if fail.matches(key, obj) {
				return readErr
			}
			return c.Get(ctx, key, obj, opts...)
		},
	}).Build()
}

func newControllerInputs(variant operatorv1.ProductVariant, objs ...client.Object) controller.Inputs {
	return newControllerInputsWith(newFakeClient(), variant, objs...)
}

func newFakeClient() client.WithWatch {
	return ctrlrfake.DefaultFakeClientBuilder(installationScheme()).Build()
}

func installationScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
	return scheme
}

// newControllerInputsWith is newControllerInputs against a caller-supplied client.
func newControllerInputsWith(c client.WithWatch, variant operatorv1.ProductVariant, objs ...client.Object) controller.Inputs {
	for _, o := range objs {
		Expect(c.Create(context.Background(), o)).NotTo(HaveOccurred())
	}

	certManager, err := certificatemanager.Create(c, nil, "", common.OperatorNamespace(), certificatemanager.AllowCACreation())
	Expect(err).NotTo(HaveOccurred())
	trustedBundle := certManager.CreateTrustedBundle()

	return controller.Inputs{
		RenderInputs: render.Inputs{
			Installation:       &operatorv1.InstallationSpec{Variant: variant},
			FelixConfiguration: &v3.FelixConfiguration{},
			TrustedBundle:      trustedBundle,
			ClusterDomain:      "cluster.local",
		},
		Client:             c,
		CertificateManager: certManager,
	}
}
