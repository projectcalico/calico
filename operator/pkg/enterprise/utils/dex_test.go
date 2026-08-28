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

package utils_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	opv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/enterprise/utils"
)

var _ = Describe("DexEnabled", func() {
	DescribeTable("should correctly determine whether Dex is enabled",
		func(authentication *opv1.Authentication, expectedResult bool) {
			Expect(utils.DexEnabled(authentication)).To(Equal(expectedResult))
		},
		Entry("when authentication is nil", nil, false),
		Entry("when authentication is not nil and OIDC is nil",
			&opv1.Authentication{Spec: opv1.AuthenticationSpec{OIDC: nil}}, true),
		Entry("when authentication is not nil and OIDC type is OIDCTypeTigera",
			&opv1.Authentication{Spec: opv1.AuthenticationSpec{OIDC: &opv1.AuthenticationOIDC{Type: opv1.OIDCTypeTigera}}}, false),
		Entry("when authentication is not nil and OIDC type is different",
			&opv1.Authentication{Spec: opv1.AuthenticationSpec{OIDC: &opv1.AuthenticationOIDC{Type: opv1.OIDCTypeDex}}}, true),
	)
})
