// Copyright (c) 2017,2021 Tigera, Inc. All rights reserved.

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

package v3_test

import (
	"reflect"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	. "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
)

var (
	// gnpExtraFields is the set of fields that should be in GlobalNetworkPolicy but not
	// NetworkPolicy.
	gnpExtraFields = From("DoNotTrack", "PreDNAT", "ApplyOnForward", "NamespaceSelector")

	// npExtraFields is the set of fields that should be in NetworkPolicy but not
	// GlobalNetworkPolicy.
	npExtraFields = From()
)

// These tests verify that the NetworkPolicySpec struct and the GlobalNetworkPolicySpec struct
// are kept in sync.
var _ = Describe("NetworkPolicySpec", func() {
	var npFieldsByName map[string]reflect.StructField
	var gnpFieldsByName map[string]reflect.StructField

	BeforeEach(func() {
		npFieldsByName = fieldsByName(NetworkPolicySpec{})
		gnpFieldsByName = fieldsByName(GlobalNetworkPolicySpec{})
	})

	It("and GlobalNetworkPolicySpec shared fields should have the same tags", func() {
		for n, f := range npFieldsByName {
			if gf, ok := gnpFieldsByName[n]; ok {
				Expect(f.Tag).To(Equal(gf.Tag), "Field "+n+" had different tag")
			}
		}
	})

	It("and GlobalNetworkPolicySpec shared fields should have the same types", func() {
		for n, f := range npFieldsByName {
			if gf, ok := gnpFieldsByName[n]; ok {
				Expect(f.Type).To(Equal(gf.Type), "Field "+n+" had different type")
			}
		}
	})

	It("should not have any unexpected fields that GlobalNetworkPolicySpec doesn't have", func() {
		for n := range npFieldsByName {
			if npExtraFields.Contains(n) {
				continue
			}
			Expect(gnpFieldsByName).To(HaveKey(n))
		}
	})

	It("should contain all expected fields of GlobalNetworkPolicySpec", func() {
		for n := range gnpFieldsByName {
			if gnpExtraFields.Contains(n) {
				continue
			}
			Expect(npFieldsByName).To(HaveKey(n))
		}
	})
})

func fieldsByName(example interface{}) map[string]reflect.StructField {
	fields := map[string]reflect.StructField{}
	t := reflect.TypeOf(example)
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		fields[f.Name] = f
	}
	return fields
}

type empty struct{}

type set map[string]empty

func From(members ...string) set {
	s := set{}
	for _, m := range members {
		s[m] = empty{}
	}
	return s
}

func (s set) Contains(item string) bool {
	_, present := s[item]
	return present
}
