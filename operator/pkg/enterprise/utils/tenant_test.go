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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	v1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/enterprise/cloudconfig"
)

var _ = Describe("TenantFromCloudConfig", func() {
	var cloudConfig *cloudconfig.CloudConfig

	BeforeEach(func() {
		cloudConfig = cloudconfig.NewCloudConfig("abc123", "tenant1", "externalES.com", "externalKibana.com", true)
	})

	It("should return a single-tenant Tenant with the Elastic configuration from the CloudConfig", func() {
		tenant := TenantFromCloudConfig(cloudConfig)
		Expect(tenant.Name).To(Equal("default"))
		Expect(tenant.Namespace).To(BeEmpty())
		Expect(tenant.MultiTenant()).To(BeFalse())
		Expect(tenant.Spec.ID).To(Equal("abc123"))
		Expect(tenant.Spec.Name).To(Equal("tenant1"))
		Expect(tenant.Spec.Elastic.URL).To(Equal("https://externalES.com:443"))
		Expect(tenant.Spec.Elastic.KibanaURL).To(Equal("https://externalKibana.com:443"))
		Expect(tenant.Spec.Elastic.MutualTLS).To(BeTrue())
	})

	It("should not declare any indices when not using single-index storage", func() {
		Expect(TenantFromCloudConfig(cloudConfig).Spec.Indices).To(BeEmpty())
	})

	It("should declare the standard index for every data type when using single-index storage", func() {
		indices := TenantFromCloudConfig(cloudConfig, WithStandardIndices()).Spec.Indices
		Expect(indices).To(HaveLen(len(v1.DataTypes)))
		for _, index := range indices {
			Expect(index.BaseIndexName).To(Equal(cloudStandardIndices[index.DataType]))
			Expect(index.BaseIndexName).ToNot(BeEmpty())
		}
	})

	It("should declare indices in a stable order", func() {
		expected := TenantFromCloudConfig(cloudConfig, WithStandardIndices()).Spec.Indices
		for i := 0; i < 10; i++ {
			Expect(TenantFromCloudConfig(cloudConfig, WithStandardIndices()).Spec.Indices).To(Equal(expected))
		}
	})

	It("should not duplicate indices when applied more than once", func() {
		once := TenantFromCloudConfig(cloudConfig, WithStandardIndices()).Spec.Indices
		twice := TenantFromCloudConfig(cloudConfig, WithStandardIndices(), WithStandardIndices()).Spec.Indices

		Expect(twice).To(HaveLen(len(v1.DataTypes)))
		Expect(twice).To(Equal(once))
	})

	It("should leave an index the Tenant already declares alone", func() {
		// An explicitly declared base index name wins over the standard one, and is not duplicated.
		declareFlowLogs := func(tenant *v1.Tenant) {
			tenant.Spec.Indices = []v1.Index{{DataType: v1.DataTypeFlowLogs, BaseIndexName: "custom_flowlogs"}}
		}

		indices := TenantFromCloudConfig(cloudConfig, declareFlowLogs, WithStandardIndices()).Spec.Indices
		Expect(indices).To(HaveLen(len(v1.DataTypes)))

		var flowLogs []v1.Index
		for _, index := range indices {
			if index.DataType == v1.DataTypeFlowLogs {
				flowLogs = append(flowLogs, index)
			}
		}
		Expect(flowLogs).To(ConsistOf(v1.Index{DataType: v1.DataTypeFlowLogs, BaseIndexName: "custom_flowlogs"}))
	})
})
