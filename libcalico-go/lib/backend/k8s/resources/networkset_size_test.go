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

package resources_test

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/openapi"
	apimachineryvalidation "k8s.io/apimachinery/pkg/api/validation"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/managedfields"
	"k8s.io/apimachinery/pkg/util/validation/field"
	k8sopenapi "k8s.io/apiserver/pkg/endpoints/openapi"
	genericapiserver "k8s.io/apiserver/pkg/server"
	openapibuilder3 "k8s.io/kube-openapi/pkg/builder3"
	openapiutil "k8s.io/kube-openapi/pkg/util"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/resources"
)

// A network set written through the projectcalico.org/v3 API server is stored in a
// crd.projectcalico.org/v1 resource, with its v3 metadata - managedFields included -
// in an annotation. Kubernetes caps the total size of annotations, so that metadata
// must not grow with the number of nets, or large sets cannot be stored at all.
var _ = Describe("Network sets written through the v3 API", func() {
	const numNets = 20000

	nets := make([]string, numNets)
	for i := range nets {
		nets[i] = fmt.Sprintf("10.%d.%d.%d/32", i>>16, (i>>8)&0xff, i&0xff)
	}

	DescribeTable("fit in CRD annotations regardless of the number of nets",
		func(obj resources.Resource) {
			written := writeThroughV3FieldManager(obj)

			crd, err := resources.ConvertCalicoResourceToK8sResource(written)
			Expect(err).NotTo(HaveOccurred())

			errs := apimachineryvalidation.ValidateAnnotations(crd.GetObjectMeta().GetAnnotations(), field.NewPath("metadata", "annotations"))
			Expect(errs).To(BeEmpty())
		},
		Entry("GlobalNetworkSet", &apiv3.GlobalNetworkSet{
			TypeMeta:   metav1.TypeMeta{Kind: apiv3.KindGlobalNetworkSet, APIVersion: apiv3.GroupVersionCurrent},
			ObjectMeta: metav1.ObjectMeta{Name: "large"},
			Spec:       apiv3.GlobalNetworkSetSpec{Nets: nets},
		}),
		Entry("NetworkSet", &apiv3.NetworkSet{
			TypeMeta:   metav1.TypeMeta{Kind: apiv3.KindNetworkSet, APIVersion: apiv3.GroupVersionCurrent},
			ObjectMeta: metav1.ObjectMeta{Name: "large", Namespace: "default"},
			Spec:       apiv3.NetworkSetSpec{Nets: nets},
		}),
	)
})

// writeThroughV3FieldManager returns obj with the managedFields the v3 API server
// records when a client creates it, using the same OpenAPI-derived type information.
func writeThroughV3FieldManager(obj resources.Resource) resources.Resource {
	scheme := runtime.NewScheme()
	Expect(apiv3.AddToScheme(scheme)).To(Succeed())

	config := genericapiserver.DefaultOpenAPIV3Config(openapi.GetOpenAPIDefinitions, k8sopenapi.NewDefinitionNamer(scheme))
	spec, err := openapibuilder3.BuildOpenAPIDefinitionsForResources(config, openapiutil.GetCanonicalTypeName(obj))
	Expect(err).NotTo(HaveOccurred())
	typeConverter, err := managedfields.NewTypeConverter(spec, false)
	Expect(err).NotTo(HaveOccurred())

	gvk := obj.GetObjectKind().GroupVersionKind()
	fieldManager, err := managedfields.NewDefaultFieldManager(
		typeConverter, runtime.UnsafeObjectConvertor(scheme), scheme, scheme, gvk, gvk.GroupVersion(), "", nil)
	Expect(err).NotTo(HaveOccurred())

	empty, err := scheme.New(gvk)
	Expect(err).NotTo(HaveOccurred())
	empty.GetObjectKind().SetGroupVersionKind(gvk)

	written := fieldManager.UpdateNoErrors(empty, obj, "test-client")
	Expect(written.(metav1.Object).GetManagedFields()).NotTo(BeEmpty())
	return written.(resources.Resource)
}
