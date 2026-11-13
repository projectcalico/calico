// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package utils

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// PoolFamilies returns the IP families pods get addresses in. It reads the
// IPPools rather than node addresses because an IPv4-only Calico cluster can run
// on dual-stack hosts, whose nodes report an IPv6 InternalIP Calico never uses.
func PoolFamilies(cli ctrlclient.Client) ([]IPFamily, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pools := &v3.IPPoolList{}
	if err := cli.List(ctx, pools); err != nil {
		return nil, fmt.Errorf("listing IPPools: %w", err)
	}
	return poolFamilies(pools.Items)
}

func poolFamilies(pools []v3.IPPool) ([]IPFamily, error) {
	have := map[IPFamily]bool{}
	var skipped []string
	for _, p := range pools {
		if reason := poolSkipReason(p); reason != "" {
			skipped = append(skipped, fmt.Sprintf("%s (%s)", p.Name, reason))
			continue
		}
		ip, _, err := net.ParseCIDR(p.Spec.CIDR)
		if err != nil {
			return nil, fmt.Errorf("IPPool %s has unparseable CIDR %q: %w", p.Name, p.Spec.CIDR, err)
		}
		if ip.To4() != nil {
			have[IPv4] = true
		} else {
			have[IPv6] = true
		}
	}
	var families []IPFamily
	for _, f := range allIPFamilies {
		if have[f] {
			families = append(families, f)
		}
	}
	if len(families) == 0 {
		if len(skipped) == 0 {
			return nil, fmt.Errorf("no IPPools found")
		}
		return nil, fmt.Errorf("no IPPool assigns pod addresses automatically: %s", strings.Join(skipped, ", "))
	}
	return families, nil
}

// poolSkipReason is "" for a pool that automatically gives pods addresses; the
// others don't decide which families a pod can have.
func poolSkipReason(p v3.IPPool) string {
	if p.Spec.Disabled {
		return "disabled"
	}
	if len(p.Spec.AllowedUses) > 0 && !slices.Contains(p.Spec.AllowedUses, v3.IPPoolAllowedUseWorkload) {
		return fmt.Sprintf("allowedUses %v", p.Spec.AllowedUses)
	}
	if p.Spec.AssignmentMode != nil && *p.Spec.AssignmentMode != v3.Automatic {
		return fmt.Sprintf("assignmentMode %s", *p.Spec.AssignmentMode)
	}
	return ""
}
