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

package utils

import (
	"context"
	"strings"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// IPPoolsForFamily returns the cluster's IP pools of one address family. A
// cluster installed with a named pool, or on a provider's IPAM, has no pool
// called default-ipv4-ippool, so select by family rather than by name.
func IPPoolsForFamily(ctx context.Context, cli ctrlclient.Client, ipv6 bool) ([]v3.IPPool, error) {
	pools := &v3.IPPoolList{}
	if err := cli.List(ctx, pools); err != nil {
		return nil, err
	}
	var matching []v3.IPPool
	for _, pool := range pools.Items {
		if strings.Contains(pool.Spec.CIDR, ":") == ipv6 {
			matching = append(matching, pool)
		}
	}
	return matching, nil
}
