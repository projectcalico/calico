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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/enterprise/cloudconfig"
)

// ToTenant converts the given CloudConfig structure to a Tenant object.
// This allows controllers that have been converted to support multi-tenancy to still leverage
// the single-tenant CloudConfig structure using the same code path as in multi-tenancy.
func TenantFromCloudConfig(c *cloudconfig.CloudConfig) *v1.Tenant {
	return &v1.Tenant{
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
}
