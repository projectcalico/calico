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
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/uuid"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

var _ = Describe("Profile tests with fake clientSet", func() {
	var clientSet *FakeClientSetWithListRevAndFiltering
	var client *profileClient

	BeforeEach(func() {
		clientSet = NewFakeClientSetWithListRevAndFiltering()

		// Use unique revision for each of the base types so we can verify that
		// they flow through correctly.
		clientSet.CurrentListRevisionByType["Namespace"] = "100"
		clientSet.CurrentListRevisionByType["ServiceAccount"] = "200"

		defaultNS := &v1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "default",
				ResourceVersion: "10",
				UID:             uuid.NewUUID(),
			},
		}
		defaultNS, err := clientSet.CoreV1().Namespaces().Create(context.TODO(), defaultNS, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		defaultSA := &v1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "default",
				Namespace:       "default",
				ResourceVersion: "20",
				UID:             uuid.NewUUID(),
			},
		}
		defaultSA, err = clientSet.CoreV1().ServiceAccounts("default").Create(context.TODO(), defaultSA, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		client = NewProfileClient(clientSet).(*profileClient)
	})

	It("should list all and return the collection revision", func() {
		list, err := client.List(context.TODO(), model.ResourceListOptions{}, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(list.KVPairs).To(HaveLen(3))
		Expect(list.Revision).To(Equal("100/200"),
			"revision should match the combined collection versions")
	})

	It("should only return the default allow profile by name", func() {
		list, err := client.List(context.TODO(), model.ResourceListOptions{
			Name: "projectcalico-default-allow",
		}, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(list.KVPairs).To(HaveLen(1))
		Expect(list.Revision).To(Equal("1"),
			"revision should only relate to the namespace collection")
	})

	It("should only query namespaces when filtering to a namespace profile name", func() {
		list, err := client.List(context.TODO(), model.ResourceListOptions{
			Name: "kns.default",
		}, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(list.KVPairs).To(HaveLen(1))
		Expect(list.Revision).To(Equal("100/"),
			"revision should only relate to the namespace collection")
	})

	It("should only query service accounts when filtering to a service account profile name", func() {
		list, err := client.List(context.TODO(), model.ResourceListOptions{
			Name: "ksa.default.default",
		}, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(list.KVPairs).To(HaveLen(1))
		Expect(list.Revision).To(Equal("/200"),
			"revision should only relate to the sa collection")
	})
})
