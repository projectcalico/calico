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
	k8sapi "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

var _ = Describe("Service tests with fake clientSet", func() {
	var clientSet *FakeClientSetWithListRevAndFiltering
	var client *serviceClient

	BeforeEach(func() {
		clientSet = NewFakeClientSetWithListRevAndFiltering()
		client = NewServiceClient(clientSet).(*serviceClient)

		service, err := clientSet.CoreV1().Services("some-ns").Create(context.TODO(), &k8sapi.Service{
			ObjectMeta: metav1.ObjectMeta{
				ResourceVersion: "10",
				Name:            "some-service",
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(service).NotTo(BeNil())
	})

	It("should list all and return the collection revision", func() {
		list, err := client.List(context.TODO(), model.ResourceListOptions{}, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(list.KVPairs).To(HaveLen(1))
		Expect(list.Revision).To(Equal("123"),
			"revision should match the collection version")

		clientSet.DefaultCurrentListRevision = "124"
		list, err = client.List(context.TODO(), model.ResourceListOptions{}, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(list.KVPairs).To(HaveLen(1))
		Expect(list.Revision).To(Equal("124"),
			"revision should match the collection version")
	})

	It("should filter by name, returning correct revision", func() {
		// Name only.
		list, err := client.List(context.TODO(), model.ResourceListOptions{
			Name: "some-service",
		}, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(list.KVPairs).To(HaveLen(1))
		Expect(list.Revision).To(Equal("123"),
			"revision should match the collection version")

		// With updated revision.
		clientSet.DefaultCurrentListRevision = "124"
		list, err = client.List(context.TODO(), model.ResourceListOptions{
			Name: "some-service",
		}, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(list.KVPairs).To(HaveLen(1))
		Expect(list.Revision).To(Equal("124"),
			"revision should match the collection version")

		// Wrong name, doesn't match anything.
		list, err = client.List(context.TODO(), model.ResourceListOptions{
			Name: "some-other-service",
		}, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(list.KVPairs).To(HaveLen(0))
		Expect(list.Revision).To(Equal("124"),
			"revision should match the collection version, even if name doesn't match anything")

		// Correct name, wrong namespace.
		list, err = client.List(context.TODO(), model.ResourceListOptions{
			Name:      "some-service",
			Namespace: "some-other-ns",
		}, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(list.KVPairs).To(HaveLen(0))
		Expect(list.Revision).To(Equal("124"),
			"revision should match the collection version, even if namespace doesn't match anything")
	})
})
