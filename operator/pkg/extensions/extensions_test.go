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

package extensions_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/controller"
	"github.com/projectcalico/calico/operator/pkg/extensions"
	"github.com/projectcalico/calico/operator/pkg/extensions/extensionstest"
	"github.com/projectcalico/calico/operator/pkg/render"
)

func configMap(name string) client.Object {
	return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name}}
}

func baseComponent() render.Component {
	return extensionstest.StubComponent{Create: []client.Object{configMap("base")}}
}

func inputsFor(variant operatorv1.ProductVariant) render.Inputs {
	return render.Inputs{Installation: &operatorv1.InstallationSpec{Variant: variant}}
}

func addConfigMap(create, del []client.Object) ([]client.Object, []client.Object) {
	return append(create, configMap("added")), del
}

var _ = Describe("Decorate", func() {
	It("runs the modifier over what the component rendered", func() {
		c := extensions.Decorate(baseComponent(), inputsFor(operatorv1.CalicoEnterprise), operatorv1.CalicoEnterprise, addConfigMap)

		create, _ := c.Objects()
		Expect(create).To(HaveLen(2))
		_, ok := extensions.FindObject[*corev1.ConfigMap](create, "added")
		Expect(ok).To(BeTrue())
	})

	It("runs the modifier for the deprecated Enterprise spelling", func() {
		//nolint:staticcheck // SA1019: the deprecated spelling is what this covers
		c := extensions.Decorate(baseComponent(), inputsFor(operatorv1.TigeraSecureEnterprise), operatorv1.CalicoEnterprise, addConfigMap)

		create, _ := c.Objects()
		Expect(create).To(HaveLen(2))
	})

	It("leaves the component alone when the Installation asks for another variant", func() {
		c := extensions.Decorate(baseComponent(), inputsFor(operatorv1.Calico), operatorv1.CalicoEnterprise, addConfigMap)

		create, _ := c.Objects()
		Expect(create).To(HaveLen(1))
	})

	It("leaves the component alone when there is no Installation", func() {
		c := extensions.Decorate(baseComponent(), render.Inputs{}, operatorv1.CalicoEnterprise, addConfigMap)

		create, _ := c.Objects()
		Expect(create).To(HaveLen(1))
	})
})

var _ = Describe("the zero value Extensions", func() {
	It("runs the base behavior for every controller", func() {
		var e extensions.Extensions

		Expect(e.Installation().ProductVersion()).NotTo(BeEmpty())
		Expect(e.Installation().Images()).To(BeNil())
		Expect(e.Windows().Watches(nil)).NotTo(HaveOccurred())

		ci, keyPairs, err := e.ClusterConnection().ExtendInputs(context.Background(), controller.Inputs{})
		Expect(err).NotTo(HaveOccurred())
		Expect(keyPairs).To(BeEmpty())
		Expect(ci.RenderInputs.Extension).To(BeNil())

		create, _ := e.APIServer().Modify(baseComponent(), render.Inputs{}).Objects()
		Expect(create).To(HaveLen(1))
	})
})

var _ = Describe("the base ManagementClusterConnection validation", func() {
	var e extensions.Extensions

	It("accepts a connection that uses none of the Enterprise fields", func() {
		cr := &operatorv1.ManagementClusterConnection{}
		Expect(e.ClusterConnection().ValidateAndDefault(cr)).NotTo(HaveOccurred())
		Expect(cr.Spec.Impersonation).To(BeNil())
	})

	It("rejects impersonation, which only Enterprise Voltron honors", func() {
		cr := &operatorv1.ManagementClusterConnection{
			Spec: operatorv1.ManagementClusterConnectionSpec{Impersonation: &operatorv1.Impersonation{}},
		}
		Expect(e.ClusterConnection().ValidateAndDefault(cr)).To(MatchError(ContainSubstring("Impersonation must be unset")))
	})

	It("rejects a public CA, since only Enterprise guardian trusts the system bundle", func() {
		cr := &operatorv1.ManagementClusterConnection{
			Spec: operatorv1.ManagementClusterConnectionSpec{
				TLS: &operatorv1.ManagementClusterTLS{CA: operatorv1.CATypePublic},
			},
		}
		Expect(e.ClusterConnection().ValidateAndDefault(cr)).To(MatchError(ContainSubstring("cannot be public")))
	})

	It("accepts the Tigera CA", func() {
		cr := &operatorv1.ManagementClusterConnection{
			Spec: operatorv1.ManagementClusterConnectionSpec{
				TLS: &operatorv1.ManagementClusterTLS{CA: operatorv1.CATypeTigera},
			},
		}
		Expect(e.ClusterConnection().ValidateAndDefault(cr)).NotTo(HaveOccurred())
	})
})

var _ = Describe("MustFindObject", func() {
	objs := []client.Object{configMap("present")}

	It("should return the named object", func() {
		Expect(extensions.MustFindObject[*corev1.ConfigMap](objs, "present").Name).To(Equal("present"))
	})

	It("should panic when the object is absent", func() {
		Expect(func() {
			extensions.MustFindObject[*corev1.ConfigMap](objs, "missing")
		}).To(PanicWith(ContainSubstring(`BUG: no object named "missing"`)))
	})

	It("should panic when the object has a different type", func() {
		Expect(func() {
			extensions.MustFindObject[*corev1.Secret](objs, "present")
		}).To(PanicWith(ContainSubstring(`BUG: no object named "present"`)))
	})
})
