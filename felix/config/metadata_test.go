// Copyright (c) 2024 Tigera, Inc. All rights reserved.
//
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

package config

import (
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	v1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

var _ = ginkgo.Describe("Docs metadata", func() {
	ginkgo.It("should load the metadata", func() {
		// This also exercises the enum-marker assertions against the real
		// FelixConfiguration CRD, so it fails if a new field regresses.
		params, err := CombinedFieldInfo()
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
		gomega.Expect(params).NotTo(gomega.BeEmpty())
	})
})

func enum(vals ...string) []v1.JSON {
	var out []v1.JSON
	for _, v := range vals {
		out = append(out, v1.JSON{Raw: []byte(`"` + v + `"`)})
	}
	return out
}

var _ = ginkgo.Describe("Enum marker assertions", func() {
	ginkgo.DescribeTable("crdFieldHasNestedEnum",
		func(prop v1.JSONSchemaProps, expected bool) {
			gomega.Expect(crdFieldHasNestedEnum(prop)).To(gomega.Equal(expected))
		},
		ginkgo.Entry("top-level enum is fine",
			v1.JSONSchemaProps{Enum: enum("Auto", "Strict")}, false),
		ginkgo.Entry("no enum at all is fine",
			v1.JSONSchemaProps{Type: "string"}, false),
		ginkgo.Entry("enum nested under allOf (duplicate marker) is flagged",
			v1.JSONSchemaProps{AllOf: []v1.JSONSchemaProps{
				{Enum: enum("Auto", "Strict")},
				{Enum: enum("Auto", "Strict")},
			}}, true),
		ginkgo.Entry("allOf without any enum is fine",
			v1.JSONSchemaProps{AllOf: []v1.JSONSchemaProps{{Type: "string"}}}, false),
	)

	ginkgo.DescribeTable("checkEnumMarkers",
		func(field *FieldInfo, expectErr bool) {
			err := checkEnumMarkers([]*FieldInfo{field})
			if expectErr {
				gomega.Expect(err).To(gomega.HaveOccurred())
			} else {
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
			}
		},
		ginkgo.Entry("closed set with CRD enum is fine",
			&FieldInfo{NameYAML: "x", StringSchema: "One of: `A`, `B`", YAMLEnumValues: []string{"A", "B"}}, false),
		ginkgo.Entry("closed set with no CRD enum is flagged",
			&FieldInfo{NameYAML: "x", NameGoAPI: "X", StringSchema: "One of: `A`, `B`"}, true),
		ginkgo.Entry("allow-listed closed set with no CRD enum is fine",
			&FieldInfo{NameYAML: "bpfCTLBLogFilter", StringSchema: "One of: `all`"}, false),
		ginkgo.Entry("non closed-set string is fine",
			&FieldInfo{NameYAML: "x", StringSchema: "String."}, false),
		ginkgo.Entry("field not exposed in the CRD is fine",
			&FieldInfo{NameYAML: "", StringSchema: "One of: `A`, `B`"}, false),
	)
})
