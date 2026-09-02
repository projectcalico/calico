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
	"fmt"
	"sort"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/enterprise/cloudconfig"
)

// TenantOption customizes the Tenant that TenantFromCloudConfig returns.
type TenantOption func(*v1.Tenant)

// WithStandardIndices declares the standard single-index base names on the Tenant. Only clusters
// that have migrated to single-index storage should ask for them: index base names are otherwise
// left off the artificial single-tenant Tenant, and components fall back to their default names.
//
// Data types the Tenant already declares are left alone, so that applying this option more than
// once - or alongside one that declares its own indices - neither duplicates an index nor
// overrides an explicit base index name.
func WithStandardIndices() TenantOption {
	return func(tenant *v1.Tenant) {
		declared := make(map[v1.DataType]bool, len(tenant.Spec.Indices))
		for _, index := range tenant.Spec.Indices {
			declared[index.DataType] = true
		}

		for dataType := range v1.DataTypes {
			if declared[dataType] {
				continue
			}
			tenant.Spec.Indices = append(tenant.Spec.Indices, v1.Index{DataType: dataType, BaseIndexName: cloudStandardIndices[dataType]})
		}

		// DataTypes is a map, so iteration order is random. Sort by data type to keep the generated
		// index list - and therefore the env vars rendered from it - stable across reconciles.
		sort.Slice(tenant.Spec.Indices, func(i, j int) bool {
			return tenant.Spec.Indices[i].DataType < tenant.Spec.Indices[j].DataType
		})
	}
}

// WithStandardIndicesIf applies WithStandardIndices only if useSingleIndex is set, for callers that
// carry that flag around as a bool.
func WithStandardIndicesIf(useSingleIndex bool) TenantOption {
	if !useSingleIndex {
		return func(*v1.Tenant) {}
	}
	return WithStandardIndices()
}

// cloudStandardIndices maps each data type to the standard index base name used by clusters that
// have migrated to single-index storage.
var cloudStandardIndices = map[v1.DataType]string{
	v1.DataTypeAlerts:               "calico_alerts_standard",
	v1.DataTypeAuditLogs:            "calico_auditlogs_standard",
	v1.DataTypeBGPLogs:              "calico_bgplogs_standard",
	v1.DataTypeComplianceBenchmarks: "calico_compliance_benchmarks_results_standard",
	v1.DataTypeComplianceReports:    "calico_compliance_reports_standard",
	v1.DataTypeComplianceSnapshots:  "calico_compliance_snapshots_standard",
	v1.DataTypeDNSLogs:              "calico_dnslogs_standard",
	v1.DataTypeFlowLogs:             "calico_flowlogs_standard",
	v1.DataTypeL7Logs:               "calico_l7logs_standard",
	v1.DataTypeRuntimeReports:       "calico_runtime_reports_standard",
	v1.DataTypeThreatFeedsDomainSet: "calico_threatfeeds_domainnameset_standard",
	v1.DataTypeThreatFeedsIPSet:     "calico_threatfeeds_ipset_standard",
	v1.DataTypeWAFLogs:              "calico_waflogs_standard",
	v1.DataTypePolicyActivity:       "calico_policy_activity_standard",
}

// TenantFromCloudConfig converts the given CloudConfig structure to a Tenant object.
// This allows controllers that have been converted to support multi-tenancy to still leverage
// the single-tenant CloudConfig structure using the same code path as in multi-tenancy.
func TenantFromCloudConfig(c *cloudconfig.CloudConfig, opts ...TenantOption) *v1.Tenant {
	tenant := &v1.Tenant{
		// We don't specify a Namespace for this tenant because it represents a singular tenant installed
		// in this management cluster. The signals to the render code that this is a single-tenant cluster and not
		// a cluster capable of multi-tenancy.
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec: v1.TenantSpec{
			ID:   c.TenantId(),
			Name: c.TenantName(),
			Elastic: &v1.TenantElasticSpec{
				URL:       fmt.Sprintf("https://%s:443", c.ExternalESDomain()),
				KibanaURL: fmt.Sprintf("https://%s:443", c.ExternalKibanaDomain()),
				MutualTLS: c.EnableMTLS(),
			},
		},
	}

	for _, opt := range opts {
		opt(tenant)
	}

	return tenant
}
