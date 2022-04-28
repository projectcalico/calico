// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/upgrade/migrator/clients/v1/k8s/custom"
	"github.com/projectcalico/calico/libcalico-go/lib/upgrade/migrator/clients/v1/k8s/resources"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Global Felix config conversion methods", func() {

	converter := resources.GlobalFelixConfigConverter{}

	// Define some useful test data.
	listIncomplete := model.GlobalConfigListOptions{}

	// Compatible set of list, key and name (used for Key to Name conversion)
	list1 := model.GlobalConfigListOptions{
		Name: "AbCd",
	}
	key1 := model.GlobalConfigKey{
		Name: "AbCd",
	}
	name1 := "abcd"

	// Compatible set of KVPair and Kubernetes Resource.
	value1 := "test"
	kvp1 := &model.KVPair{
		Key:      key1,
		Value:    value1,
		Revision: "rv",
	}
	res1 := &custom.GlobalFelixConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name1,
			ResourceVersion: "rv",
		},
		Spec: custom.GlobalFelixConfigSpec{
			Name:  key1.Name,
			Value: value1,
		},
	}

	It("should convert an incomplete ListInterface to no Key", func() {
		Expect(converter.ListInterfaceToKey(listIncomplete)).To(BeNil())
	})

	It("should convert a qualified ListInterface to the equivalent Key", func() {
		Expect(converter.ListInterfaceToKey(list1)).To(Equal(key1))
	})

	It("should convert a Key to the equivalent resource name", func() {
		n, err := converter.KeyToName(key1)
		Expect(err).NotTo(HaveOccurred())
		Expect(n).To(Equal(name1))
	})

	It("should not convert a resource name to the equivalent Key - this is not possible due to case switching", func() {
		_, err := converter.NameToKey("test")
		Expect(err).To(HaveOccurred())
	})

	It("should convert between a KVPair and the equivalent Kubernetes resource", func() {
		r, err := converter.FromKVPair(kvp1)
		Expect(err).NotTo(HaveOccurred())
		Expect(r.GetObjectMeta().GetName()).To(Equal(res1.Name))
		Expect(r.GetObjectMeta().GetResourceVersion()).To(Equal(res1.ResourceVersion))
		Expect(r).To(BeAssignableToTypeOf(&custom.GlobalFelixConfig{}))
		Expect(r.(*custom.GlobalFelixConfig).Spec).To(Equal(res1.Spec))
	})

	It("should convert between a Kuberenetes resource and the equivalent KVPair", func() {
		kvp, err := converter.ToKVPair(res1)
		Expect(err).NotTo(HaveOccurred())
		Expect(kvp.Key).To(Equal(kvp1.Key))
		Expect(kvp.Revision).To(Equal(kvp1.Revision))
		Expect(kvp.Value).To(BeAssignableToTypeOf(value1))
		Expect(kvp.Value).To(Equal(kvp1.Value))
	})
})
