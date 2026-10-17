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

package ipam

import (
	"fmt"
	"slices"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"

	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

// poolRequest is what an automatic assignment asks of the IP pools.
type poolRequest struct {
	// requested names the pools the caller asked for. Named pools skip the node selector, namespace selector and
	// AssignmentMode checks.
	requested []net.IPNet

	// host names the requester in errors. The node's own name can be empty, depending on the datastore.
	host string

	node         internalapi.Node
	namespace    *corev1.Namespace
	use          v3.IPPoolAllowedUse
	maxPrefixLen int
}

// rejectReason records why a candidate pool did not qualify. The zero value means it qualified.
type rejectReason string

const (
	rejectAssignmentMode    rejectReason = "assignment mode is not Automatic"
	rejectNodeSelector      rejectReason = "node selector does not match"
	rejectNamespaceSelector rejectReason = "namespace selector does not match"
	rejectUse               rejectReason = "allowed uses do not match"
)

// poolCandidate is a pool considered for a request, with the reason it was rejected.
type poolCandidate struct {
	pool   v3.IPPool
	reason rejectReason
}

// poolQualification holds every candidate pool in preference order.
type poolQualification struct {
	candidates []poolCandidate
}

func (q *poolQualification) add(pool v3.IPPool, reason rejectReason) {
	if reason != "" {
		log.Debugf("IP pool %s rejected: %s", pool.Name, reason)
	}
	q.candidates = append(q.candidates, poolCandidate{pool: pool, reason: reason})
}

// qualified returns the pools the request may allocate from.
func (q poolQualification) qualified() []v3.IPPool {
	return q.filter(func(r rejectReason) bool { return r == "" })
}

// selecting returns the pools that pass every rule except allowed use. Affine blocks from these pools are kept even
// when this request can't allocate from them.
func (q poolQualification) selecting() []v3.IPPool {
	return q.filter(func(r rejectReason) bool { return r == "" || r == rejectUse })
}

func (q poolQualification) filter(keep func(rejectReason) bool) []v3.IPPool {
	var pools []v3.IPPool
	for _, c := range q.candidates {
		if keep(c.reason) {
			pools = append(pools, c.pool)
		}
	}
	return pools
}

// qualifyPools decides which pools an automatic assignment may draw from. The input must already be limited to
// allocatable pools, as GetEnabledPools returns them.
func qualifyPools(req poolRequest, enabledPools []v3.IPPool) (poolQualification, error) {
	log.Debugf("enabled pools: %v", enabledPools)
	log.Debugf("requested pools: %v", req.requested)

	fitting := map[string]v3.IPPool{}
	for _, p := range enabledPools {
		if p.Spec.BlockSize > req.maxPrefixLen {
			log.Warningf("skipping pool %v due to blockSize %d bigger than %d", p, p.Spec.BlockSize, req.maxPrefixLen)
			continue
		}
		_, cidr, err := net.ParseCIDR(p.Spec.CIDR)
		if err != nil {
			log.WithError(err).Errorf("Pool %s has invalid CIDR %s", p.Name, p.Spec.CIDR)
			return poolQualification{}, err
		}
		fitting[cidr.String()] = p
	}
	if len(fitting) == 0 {
		return poolQualification{}, ErrNoQualifiedPool
	}

	var qualification poolQualification
	if len(req.requested) > 0 {
		for _, rp := range req.requested {
			cidr := rp.Network()
			pool, ok := fitting[cidr.String()]
			if !ok {
				return poolQualification{}, fmt.Errorf("the given pool (%s) does not exist, or is not enabled", cidr.String())
			}
			qualification.add(pool, checkUse(pool, req.use))
		}
	} else {
		// Unlike named pools, automatic selection doesn't check each pool's block size against maxPrefixLen.
		for _, pool := range enabledPools {
			reason, err := checkSelection(pool, req)
			if err != nil {
				return poolQualification{}, err
			}
			if reason == "" {
				reason = checkUse(pool, req.use)
			}
			qualification.add(pool, reason)
		}
	}

	if len(qualification.selecting()) == 0 {
		return poolQualification{}, fmt.Errorf("no configured Calico pools for node %s", req.host)
	}
	if len(qualification.qualified()) == 0 {
		return poolQualification{}, fmt.Errorf("%w, no pools match the required use (%v)", ErrNoQualifiedPool, req.use)
	}
	return qualification, nil
}

// checkSelection applies the rules that only automatic selection uses.
func checkSelection(pool v3.IPPool, req poolRequest) (rejectReason, error) {
	if *pool.Spec.AssignmentMode != v3.Automatic {
		return rejectAssignmentMode, nil
	}

	nodeMatches, err := SelectsNode(pool, req.node)
	if err != nil {
		log.WithError(err).WithField("pool", pool).Error("failed to determine if node matches pool")
		return "", err
	}
	if !nodeMatches {
		return rejectNodeSelector, nil
	}

	namespaceMatches, err := SelectsNamespace(pool, req.namespace)
	if err != nil {
		log.WithError(err).WithField("pool", pool).Error("failed to determine if namespace matches pool")
		return "", err
	}
	if !namespaceMatches {
		return rejectNamespaceSelector, nil
	}
	return "", nil
}

func checkUse(pool v3.IPPool, use v3.IPPoolAllowedUse) rejectReason {
	if slices.Contains(pool.Spec.AllowedUses, use) {
		return ""
	}
	return rejectUse
}

// qualifyPoolForIP applies the rules for assigning a specific IP. Only allowed uses are checked, and only when the
// caller declares a use.
func qualifyPoolForIP(ip net.IP, pool v3.IPPool, use v3.IPPoolAllowedUse) error {
	if use == "" || slices.Contains(pool.Spec.AllowedUses, use) {
		return nil
	}
	return fmt.Errorf("IP address %s is in IP pool %q, which is not allowed for use %q (allowedUses: %v)", ip, pool.Name, use, pool.Spec.AllowedUses)
}
