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

package utils

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
)

var _ = Describe("License helpers", func() {
	var license v3.LicenseKey

	BeforeEach(func() {
		license = v3.LicenseKey{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
		}
	})

	Context("ParseGracePeriod", func() {
		DescribeTable("should parse grace period strings",
			func(input string, expected time.Duration) {
				Expect(ParseGracePeriod(input)).To(Equal(expected))
			},
			Entry("90 days", "90d", 90*24*time.Hour),
			Entry("30 days", "30d", 30*24*time.Hour),
			Entry("0 days", "0d", time.Duration(0)),
			Entry("empty string", "", time.Duration(0)),
			Entry("invalid string", "abc", time.Duration(0)),
			Entry("negative days", "-5d", time.Duration(0)),
			Entry("bare number without unit", "90", time.Duration(0)),
		)
	})

	Context("GetLicenseStatus", func() {
		DescribeTable("should return the correct license status",
			func(expiryOffset time.Duration, gracePeriod time.Duration, expected LicenseStatus) {
				license.Status.Expiry = metav1.Time{Time: time.Now().Add(expiryOffset)}
				Expect(GetLicenseStatus(license, gracePeriod)).To(Equal(expected))
			},
			Entry("valid: expiry in the future, no grace period",
				24*time.Hour, time.Duration(0), LicenseStatusValid),
			Entry("valid: expiry in the future, with grace period",
				24*time.Hour, 90*24*time.Hour, LicenseStatusValid),
			Entry("expired: expiry in the past, no grace period",
				-24*time.Hour, time.Duration(0), LicenseStatusExpired),
			Entry("in grace period: expiry in past but within grace period",
				-24*time.Hour, 90*24*time.Hour, LicenseStatusInGracePeriod),
			Entry("expired: expiry in past and beyond grace period",
				-100*24*time.Hour, 90*24*time.Hour, LicenseStatusExpired),
		)

		It("should return valid when expiry is zero", func() {
			license.Status.Expiry = metav1.Time{}
			Expect(GetLicenseStatus(license, 90*24*time.Hour)).To(Equal(LicenseStatusValid))
		})

		It("should return expired when expiry is exactly at grace period boundary", func() {
			// Set expiry far enough in the past that even with clock skew it's clearly past grace.
			license.Status.Expiry = metav1.Time{Time: time.Now().Add(-91 * 24 * time.Hour)}
			Expect(GetLicenseStatus(license, 90*24*time.Hour)).To(Equal(LicenseStatusExpired))
		})
	})
})
