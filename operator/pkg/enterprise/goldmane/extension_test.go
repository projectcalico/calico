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

package goldmane_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/enterprise"
	eoptions "github.com/projectcalico/calico/operator/pkg/enterprise/options"
	"github.com/projectcalico/calico/operator/pkg/render"
	rgoldmane "github.com/projectcalico/calico/operator/pkg/render/goldmane"
	"github.com/projectcalico/calico/operator/pkg/tls/certificatemanagement"
)

var _ = Describe("goldmane enterprise render extension", func() {
	component := func(variant operatorv1.ProductVariant) render.Component {
		return rgoldmane.Goldmane(&rgoldmane.Configuration{
			Installation:          &operatorv1.InstallationSpec{Variant: variant},
			TrustedCertBundle:     certificatemanagement.CreateTrustedBundle(nil),
			GoldmaneServerKeyPair: certificatemanagement.NewKeyPair(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: rgoldmane.GoldmaneKeyPairSecret}}, nil, ""),
			Goldmane:              &operatorv1.Goldmane{},
		})
	}

	modify := func(variant operatorv1.ProductVariant) ([]client.Object, []client.Object) {
		ext := enterprise.New(variant, eoptions.Options{}).Goldmane()
		ri := render.Inputs{Installation: &operatorv1.InstallationSpec{Variant: variant}}
		return ext.Modify(component(variant), ri).Objects()
	}

	It("deletes everything goldmane renders on Enterprise", func() {
		create, del := modify(operatorv1.CalicoEnterprise)
		Expect(create).To(BeEmpty())
		Expect(del).NotTo(BeEmpty())
	})

	It("leaves the component alone on Calico", func() {
		create, _ := modify(operatorv1.Calico)
		Expect(create).NotTo(BeEmpty())
	})
})
