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

package migrate

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var _ = Describe("Etcd to KDD Migration Export handling", func() {
	Context("with v1 API iptables values in the FelixConfiguration", func() {
		It("Should properly convert v1 API iptables values to v3 API values", func() {
			felixConfig := apiv3.NewFelixConfiguration()
			felixConfig.Spec = apiv3.FelixConfigurationSpec{
				DefaultEndpointToHostAction: "DROP",
				IptablesFilterAllowAction:   "ACCEPT",
				IptablesMangleAllowAction:   "RETURN",
				IptablesFilterDenyAction:    "DROP",
			}

			ConvertIptablesFields(felixConfig)
			Expect(felixConfig.Spec.DefaultEndpointToHostAction).To(Equal("Drop"))
			Expect(felixConfig.Spec.IptablesFilterAllowAction).To(Equal("Accept"))
			Expect(felixConfig.Spec.IptablesMangleAllowAction).To(Equal("Return"))
			Expect(felixConfig.Spec.IptablesFilterDenyAction).To(Equal("Drop"))
		})

		It("Should not change v3 API iptables values", func() {
			felixConfig := apiv3.NewFelixConfiguration()
			felixConfig.Spec = apiv3.FelixConfigurationSpec{
				DefaultEndpointToHostAction: "Drop",
				IptablesFilterAllowAction:   "ACCEPT",
				IptablesMangleAllowAction:   "Return",
				IptablesFilterDenyAction:    "Drop",
			}

			ConvertIptablesFields(felixConfig)
			Expect(felixConfig.Spec.DefaultEndpointToHostAction).To(Equal("Drop"))
			Expect(felixConfig.Spec.IptablesFilterAllowAction).To(Equal("Accept"))
			Expect(felixConfig.Spec.IptablesMangleAllowAction).To(Equal("Return"))
			Expect(felixConfig.Spec.IptablesFilterDenyAction).To(Equal("Drop"))
		})

		It("Should not change any values if no iptables values are set", func() {
			felixConfig := apiv3.NewFelixConfiguration()
			felixConfig.Spec = apiv3.FelixConfigurationSpec{}

			ConvertIptablesFields(felixConfig)
			Expect(felixConfig.Spec.DefaultEndpointToHostAction).To(Equal(""))
			Expect(felixConfig.Spec.IptablesFilterAllowAction).To(Equal(""))
			Expect(felixConfig.Spec.IptablesMangleAllowAction).To(Equal(""))
			Expect(felixConfig.Spec.IptablesFilterDenyAction).To(Equal(""))
		})
	})

	It("should cover all calico resources", func() {
		allPlurals := set.FromArray(model.AllResourcePlurals())

		// Profiles are backed by k8s resources in KDD.  User cannot create
		// their own.
		allPlurals.Discard("profiles")
		// WEPs are backed by Pods in KDD.
		allPlurals.Discard("workloadendpoints")
		// LiveMigrations are backed by KubeVirt VirtualMachineInstanceMigration in KDD.
		allPlurals.Discard("livemigrations")
		// ClusterInformation is generated fresh in the new cluster.
		allPlurals.Discard("clusterinformations")
		// Not supported in KDD (OpenStack only).
		allPlurals.Discard("caliconodestatuses")
		// Handled by IPAM migration code.
		allPlurals.Discard("ipamconfigs")
		allPlurals.Discard("ipamconfigurations")
		allPlurals.Discard("blockaffinities")

		for resource := range allPlurals.All() {
			if strings.HasPrefix(resource, "kubernetes") {
				// "kubernetes"-prefixed resources are backed by Kubernetes API
				// objects, not Calico objects.
				allPlurals.Discard(resource)
			}
		}

		Expect(allV3Resources).To(ConsistOf(allPlurals.Slice()))
	})

	It("should have names for all resources", func() {
		var keys []string
		for k := range resourceDisplayMap {
			keys = append(keys, k)
		}
		Expect(keys).To(ConsistOf(allV3Resources),
			"expected to see names for the listed calico resources (only)")
	})
})
