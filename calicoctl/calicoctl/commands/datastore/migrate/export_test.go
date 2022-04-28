// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.

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

package migrate_test

import (
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/datastore/migrate"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Etcd to KDD Migration Export handling", func() {
	Context("with v1 API iptables values in the FelixConfiguration", func() {
		It("Should properly convert v1 API iptables values to v3 API values", func() {
			felixConfig := apiv3.NewFelixConfiguration()
			felixConfig.Spec = apiv3.FelixConfigurationSpec{
				DefaultEndpointToHostAction: "DROP",
				IptablesFilterAllowAction:   "ACCEPT",
				IptablesMangleAllowAction:   "RETURN",
			}

			migrate.ConvertIptablesFields(felixConfig)
			Expect(felixConfig.Spec.DefaultEndpointToHostAction).To(Equal("Drop"))
			Expect(felixConfig.Spec.IptablesFilterAllowAction).To(Equal("Accept"))
			Expect(felixConfig.Spec.IptablesMangleAllowAction).To(Equal("Return"))
		})

		It("Should not change v3 API iptables values", func() {
			felixConfig := apiv3.NewFelixConfiguration()
			felixConfig.Spec = apiv3.FelixConfigurationSpec{
				DefaultEndpointToHostAction: "Drop",
				IptablesFilterAllowAction:   "ACCEPT",
				IptablesMangleAllowAction:   "Return",
			}

			migrate.ConvertIptablesFields(felixConfig)
			Expect(felixConfig.Spec.DefaultEndpointToHostAction).To(Equal("Drop"))
			Expect(felixConfig.Spec.IptablesFilterAllowAction).To(Equal("Accept"))
			Expect(felixConfig.Spec.IptablesMangleAllowAction).To(Equal("Return"))
		})

		It("Should not change any values if no iptables values are set", func() {
			felixConfig := apiv3.NewFelixConfiguration()
			felixConfig.Spec = apiv3.FelixConfigurationSpec{}

			migrate.ConvertIptablesFields(felixConfig)
			Expect(felixConfig.Spec.DefaultEndpointToHostAction).To(Equal(""))
			Expect(felixConfig.Spec.IptablesFilterAllowAction).To(Equal(""))
			Expect(felixConfig.Spec.IptablesMangleAllowAction).To(Equal(""))
		})
	})
})
