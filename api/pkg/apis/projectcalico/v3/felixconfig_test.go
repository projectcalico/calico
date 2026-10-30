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

package v3_test

import (
	"io/fs"
	"regexp"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/api/config/crd"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/yaml"
)

// Felix only logs a warning and falls back to the default for a BPF conntrack timeout it can't
// parse, so the CRD pattern is the only place a malformed value gets rejected.
var _ = Describe("FelixConfiguration BPFConntrackTimeouts pattern", func() {
	var patterns map[string]*regexp.Regexp

	BeforeEach(func() {
		raw, err := fs.ReadFile(crd.FS(), "projectcalico.org_felixconfigurations.yaml")
		Expect(err).NotTo(HaveOccurred())

		var def apiextensionsv1.CustomResourceDefinition
		Expect(yaml.Unmarshal(raw, &def)).To(Succeed())
		Expect(def.Spec.Versions).NotTo(BeEmpty())

		patterns = map[string]*regexp.Regexp{}
		for _, v := range def.Spec.Versions {
			timeouts := v.Schema.OpenAPIV3Schema.Properties["spec"].Properties["bpfConntrackTimeouts"].Properties
			Expect(timeouts).NotTo(BeEmpty(), "version %s", v.Name)
			for name, prop := range timeouts {
				Expect(prop.Pattern).NotTo(BeEmpty(), "version %s, field %s", v.Name, name)
				patterns[v.Name+"/"+name] = regexp.MustCompile(prop.Pattern)
			}
		}
	})

	DescribeTable("validating a timeout value",
		func(value string, valid bool) {
			for field, re := range patterns {
				Expect(re.MatchString(value)).To(Equal(valid), "field %s, value %q", field, value)
			}
		},
		Entry("seconds", "10s", true),
		Entry("milliseconds", "100ms", true),
		Entry("microseconds", "250us", true),
		Entry("compound duration", "1h30m", true),
		Entry("all units combined", "1h2m3s4ms5us", true),
		Entry("fractional duration", "1.5h", true),
		Entry("fraction with no integer part", ".5s", true),
		Entry("Auto", "Auto", true),
		Entry("repeated unit", "1msms", false),
		Entry("unit with no number", "1hm", false),
		Entry("bare unit", "ms", false),
		Entry("bare decimal point", ".s", false),
		Entry("missing unit", "10", false),
		Entry("unsupported unit", "1d", false),
		Entry("lower-case auto", "auto", false),
		Entry("empty string", "", false),
	)
})
