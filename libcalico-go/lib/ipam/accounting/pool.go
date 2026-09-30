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

package accounting

import (
	"net"
	"slices"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

// BlockSize is the pool's block size, or the default for its IP version. clientv3 defaults stored pools with it.
func BlockSize(pool *v3.IPPool) int {
	if pool.Spec.BlockSize != 0 {
		return pool.Spec.BlockSize
	}
	if ip, _, err := cnet.ParseCIDR(pool.Spec.CIDR); err == nil && ip.Version() == 6 {
		return 122
	}
	return 26
}

// AllowedUses is the pool's allowed uses, or the default. clientv3 defaults stored pools with it.
func AllowedUses(pool *v3.IPPool) []v3.IPPoolAllowedUse {
	if len(pool.Spec.AllowedUses) == 0 {
		return []v3.IPPoolAllowedUse{v3.IPPoolAllowedUseWorkload, v3.IPPoolAllowedUseTunnel}
	}
	return pool.Spec.AllowedUses
}

// NodeSelector is the pool's node selector, or the default. clientv3 defaults stored pools with it.
func NodeSelector(pool *v3.IPPool) string {
	if pool.Spec.NodeSelector == "" {
		return "all()"
	}
	return pool.Spec.NodeSelector
}

// poolFor returns the pool that owns block, or nil when no pool contains it:
//
//  1. candidatePools keeps the pools of the block's address family whose CIDR contains the whole block.
//  2. preferBlockSizeMatch narrows those to the pools whose block size matches the block, when any do.
//  3. ranksBefore picks the best of what remains.
func (t *Tracker) poolFor(block *net.IPNet) *trackedPool {
	var best *trackedPool
	for _, pool := range preferBlockSizeMatch(t.candidatePools(block), block) {
		if best == nil || ranksBefore(pool, best) {
			best = pool
		}
	}
	return best
}

// candidatePools lists the pools of the block's address family whose CIDR contains the whole block.
func (t *Tracker) candidatePools(block *net.IPNet) []*trackedPool {
	blockPrefix, blockBits := block.Mask.Size()
	var out []*trackedPool
	for _, pool := range t.pools {
		if len(pool.net.Mask)*8 == blockBits && pool.prefix <= blockPrefix && pool.net.Contains(block.IP) {
			out = append(out, pool)
		}
	}
	return out
}

// preferBlockSizeMatch keeps the candidates whose block size matches the block, or all of them when none do. Block
// size is immutable, so a match is evidence the pool carved the block.
func preferBlockSizeMatch(candidates []*trackedPool, block *net.IPNet) []*trackedPool {
	blockPrefix, _ := block.Mask.Size()
	matched := slices.DeleteFunc(slices.Clone(candidates), func(pool *trackedPool) bool {
		return pool.blockSize != blockPrefix
	})
	if len(matched) == 0 {
		return candidates
	}
	return matched
}

// ranksBefore orders candidates: not an overlap loser, then narrowest, then by name. Disabling a pool says nothing
// about who carved its blocks, so it does not count.
func ranksBefore(a, b *trackedPool) bool {
	if a.lostOverlap != b.lostOverlap {
		return !a.lostOverlap
	}
	if a.prefix != b.prefix {
		return a.prefix > b.prefix
	}
	return a.ipPool.Name < b.ipPool.Name
}

// lostOverlap is whether the pool controller ruled the pool out for overlapping another. A Terminating pool is also not
// allocatable, but it keeps the blocks it still holds.
func lostOverlap(pool *v3.IPPool) bool {
	if pool.Status == nil {
		return false
	}
	for _, c := range pool.Status.Conditions {
		if c.Type == v3.IPPoolConditionAllocatable && c.Status == metav1.ConditionFalse && c.Reason == v3.IPPoolReasonCIDROverlap {
			return true
		}
	}
	return false
}
