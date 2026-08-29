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

package whisker_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/render"
	rwhisker "github.com/projectcalico/calico/operator/pkg/render/whisker"
	"github.com/projectcalico/calico/operator/pkg/tls/certificatemanagement"
)

var _ = Describe("whisker enterprise render extension", func() {
	renderInputs := func(variant operatorv1.ProductVariant) render.Inputs {
		return render.Inputs{Installation: &operatorv1.InstallationSpec{Variant: variant}}
	}

	component := func(variant operatorv1.ProductVariant) render.Component {
		return rwhisker.Whisker(&rwhisker.Configuration{
			Installation:          &operatorv1.InstallationSpec{Variant: variant},
			TrustedCertBundle:     certificatemanagement.CreateTrustedBundle(nil),
			WhiskerKeyPair:        certificatemanagement.NewKeyPair(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: rwhisker.WhiskerKeyPairSecret}}, nil, ""),
			WhiskerBackendKeyPair: certificatemanagement.NewKeyPair(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: rwhisker.WhiskerBackendKeyPairSecret}}, nil, ""),
			Whisker:               &operatorv1.Whisker{Spec: operatorv1.WhiskerSpec{Notifications: ptr.To(operatorv1.Enabled)}},
		})
	}

	It("queues everything whisker rendered for deletion", func() {
		base := component(operatorv1.CalicoEnterprise)
		baseCreate, baseDelete := base.Objects()
		Expect(baseCreate).NotTo(BeEmpty())

		create, del := ext.Whisker().Modify(base, renderInputs(operatorv1.CalicoEnterprise)).Objects()
		Expect(create).To(BeEmpty())
		Expect(del).To(HaveLen(len(baseCreate) + len(baseDelete)))
		Expect(del).To(ContainElements(baseCreate))
	})

	It("leaves whisker alone when the installation is Calico", func() {
		base := component(operatorv1.Calico)
		baseCreate, baseDelete := base.Objects()

		create, del := calicoExt.Whisker().Modify(base, renderInputs(operatorv1.Calico)).Objects()
		Expect(create).To(HaveLen(len(baseCreate)))
		Expect(del).To(HaveLen(len(baseDelete)))
	})
})
