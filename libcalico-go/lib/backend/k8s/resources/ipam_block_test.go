// Copyright (c) 2025 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package resources

import (
	"context"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/api/pkg/client/clientset_generated/clientset/scheme"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/rest/fake"

	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

var _ = Describe("ipamBlockClient tests with fake REST client", func() {
	var client K8sResourceClient
	var fakeREST *fake.RESTClient

	BeforeEach(func() {
		fakeREST = &fake.RESTClient{
			NegotiatedSerializer: serializer.WithoutConversionCodecFactory{CodecFactory: scheme.Codecs},
			GroupVersion: schema.GroupVersion{
				Group:   "crd.projectcalico.org",
				Version: "v1",
			},
			VersionedAPIPath: "/apis",
		}
		client = NewIPAMBlockClient(nil, fakeREST)
	})

	It("should list all (v3)", func() {
		l, err := client.List(context.TODO(), model.ResourceListOptions{
			Kind: libapiv3.KindIPAMBlock,
		}, "")

		// Expect an error since the client is not implemented.
		Expect(err).To(HaveOccurred())
		Expect(l).To(BeNil())

		// But we should be able to check the request...
		url := fakeREST.Req.URL
		logrus.Debug("URL: ", url)
		Expect(url.Path).To(Equal("/apis/ipamblocks"))
		Expect(url.Query()).NotTo(HaveKey("metadata.name"))
	})

	It("should list all (v1)", func() {
		l, err := client.List(context.TODO(), model.BlockListOptions{}, "")

		// Expect an error since the client is not implemented.
		Expect(err).To(HaveOccurred())
		Expect(l).To(BeNil())

		// But we should be able to check the request...
		url := fakeREST.Req.URL
		logrus.Debug("URL: ", url)
		Expect(url.Path).To(Equal("/apis/ipamblocks"))
		Expect(url.Query()).NotTo(HaveKey("metadata.name"))
	})
})
