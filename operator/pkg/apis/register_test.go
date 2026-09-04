// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package apis

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestApis(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "pkg/apis Suite")
}

var _ = Describe("RegisterTypes", func() {
	var (
		v1GV = schema.GroupVersion{Group: "crd.projectcalico.org", Version: "v1"}
		v3GV = schema.GroupVersion{Group: "projectcalico.org", Version: "v3"}
	)

	AfterEach(func() {
		extraV3Types = nil
		extraTypes = nil
	})

	// The core types stand in for a variant's, since this package cannot name one.
	registerStubs := func() {
		RegisterTypes(
			[]runtime.Object{&v3.NetworkSet{}},
			[]runtime.Object{&v3.BGPFilter{}},
		)
	}

	knows := func(s *runtime.Scheme, gv schema.GroupVersion, kind string) bool {
		_, err := s.New(gv.WithKind(kind))
		return err == nil
	}

	It("registers nothing extra when no variant registered", func() {
		s := runtime.NewScheme()
		Expect(AddToScheme(s, true)).NotTo(HaveOccurred())
		Expect(knows(s, v3GV, "BGPFilter")).To(BeFalse())
	})

	It("puts the variant's always-v3 types in projectcalico.org/v3", func() {
		registerStubs()
		s := runtime.NewScheme()
		Expect(AddToScheme(s, false)).NotTo(HaveOccurred())
		Expect(knows(s, v3GV, "NetworkSet")).To(BeTrue())
	})

	It("puts the variant's variable types in the backing group", func() {
		registerStubs()

		s := runtime.NewScheme()
		Expect(AddToScheme(s, true)).NotTo(HaveOccurred())
		Expect(knows(s, v3GV, "BGPFilter")).To(BeTrue())

		s = runtime.NewScheme()
		Expect(AddToScheme(s, false)).NotTo(HaveOccurred())
		Expect(knows(s, v1GV, "BGPFilter")).To(BeTrue())
	})
})
