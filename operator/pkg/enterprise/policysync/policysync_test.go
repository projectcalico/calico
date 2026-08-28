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

package policysync_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/enterprise/policysync"
)

var _ = Describe("ApplicationLayerRequires", func() {
	It("returns false for a nil receiver", func() {
		Expect(policysync.ApplicationLayerRequires(nil)).To(BeFalse())
	})

	It("returns false when no feature is enabled", func() {
		Expect(policysync.ApplicationLayerRequires(&operatorv1.ApplicationLayer{})).To(BeFalse())
	})

	It("returns true when LogCollection is enabled", func() {
		enabled := operatorv1.L7LogCollectionEnabled
		al := &operatorv1.ApplicationLayer{
			Spec: operatorv1.ApplicationLayerSpec{
				LogCollection: &operatorv1.LogCollectionSpec{CollectLogs: &enabled},
			},
		}
		Expect(policysync.ApplicationLayerRequires(al)).To(BeTrue())
	})

	It("returns true when WAF is enabled", func() {
		enabled := operatorv1.WAFEnabled
		Expect(policysync.ApplicationLayerRequires(&operatorv1.ApplicationLayer{
			Spec: operatorv1.ApplicationLayerSpec{WebApplicationFirewall: &enabled},
		})).To(BeTrue())
	})

	It("returns true when ApplicationLayerPolicy is enabled", func() {
		enabled := operatorv1.ApplicationLayerPolicyEnabled
		Expect(policysync.ApplicationLayerRequires(&operatorv1.ApplicationLayer{
			Spec: operatorv1.ApplicationLayerSpec{ApplicationLayerPolicy: &enabled},
		})).To(BeTrue())
	})

	It("returns true when SidecarInjection is enabled", func() {
		enabled := operatorv1.SidecarEnabled
		Expect(policysync.ApplicationLayerRequires(&operatorv1.ApplicationLayer{
			Spec: operatorv1.ApplicationLayerSpec{SidecarInjection: &enabled},
		})).To(BeTrue())
	})
})
