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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/runtime"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/extensions"
	"github.com/tigera/operator/pkg/render"
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
		Expect(reason).To(Equal(operatorv1.ResourceValidationError))
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

	It("is a no-op when the operator runs as Calico", func() {
		_, managed, err := calicoExt.Installation().ExtendInputs(ctx, newControllerInputs(operatorv1.Calico))
		Expect(err).NotTo(HaveOccurred())
		Expect(managed).To(BeEmpty())
	})
})

func newControllerInputs(variant operatorv1.ProductVariant, objs ...client.Object) controller.Inputs {
	scheme := runtime.NewScheme()
	Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
	c := ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

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
