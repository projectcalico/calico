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
	"github.com/projectcalico/calico/libcalico-go/lib/ipam/accounting"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

// poolRequest is what an automatic assignment asks of the IP pools.
type poolRequest struct {
	// requested names the pools the caller asked for.
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

// qualifyPools decides which pools an automatic assignment may draw from. The input must already be limited to
// allocatable pools, as GetEnabledPools returns them. It returns ErrNoQualifiedPool, possibly wrapped, when no pool's
// block size fits or no pool allows the use.
func qualifyPools(req poolRequest, enabledPools []v3.IPPool) (poolQualification, error) {
	log.Debugf("enabled pools: %v", enabledPools)
	log.Debugf("requested pools: %v", req.requested)

	// Index the pools whose block size fits by CIDR, so requested pools can be looked up.
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

	// Named pools bypass the selectors; otherwise every enabled pool is checked against them.
	var qualification poolQualification
	var err error
	if len(req.requested) > 0 {
		qualification, err = qualifyRequested(req, fitting)
	} else {
		qualification, err = qualifyBySelection(req, enabledPools)
	}
	if err != nil {
		return poolQualification{}, err
	}

	// Distinguish "no pool selects this node" from "none allows this use" for the caller's error.
	if !qualification.any(isSelecting) {
		return poolQualification{}, fmt.Errorf("no configured Calico pools for node %s", req.host)
	}
	if !qualification.any(isQualified) {
		return poolQualification{}, fmt.Errorf("%w, no pools match the required use (%v)", ErrNoQualifiedPool, req.use)
	}
	return qualification, nil
}

// qualifyRequested checks the pools the caller named, in the order named. A named pool must fit the block size, and
// only its allowed uses are checked.
func qualifyRequested(req poolRequest, fitting map[string]v3.IPPool) (poolQualification, error) {
	var q poolQualification
	for _, rp := range req.requested {
		cidr := rp.Network()
		pool, ok := fitting[cidr.String()]
		if !ok {
			return poolQualification{}, fmt.Errorf("the given pool (%s) does not exist, or is not enabled", cidr.String())
		}
		q.add(pool, checkUse(pool, req.use))
	}
	return q, nil
}

// qualifyBySelection checks every enabled pool against the assignment mode, the node and namespace selectors, and
// the allowed uses. Unlike named pools, it doesn't check each pool's block size against maxPrefixLen.
func qualifyBySelection(req poolRequest, enabledPools []v3.IPPool) (poolQualification, error) {
	var q poolQualification
	for _, pool := range enabledPools {
		reason, err := checkSelection(pool, req)
		if err != nil {
			return poolQualification{}, err
		}
		if reason == "" {
			reason = checkUse(pool, req.use)
		}
		q.add(pool, reason)
	}
	return q, nil
}

// add records a candidate and logs why it was rejected, if it was.
func (q *poolQualification) add(pool v3.IPPool, reason rejectReason) {
	if reason != "" {
		log.Debugf("IP pool %s rejected: %s", pool.Name, reason)
	}
	q.candidates = append(q.candidates, poolCandidate{pool: pool, reason: reason})
}

// qualified returns the pools the request may allocate from.
func (q poolQualification) qualified() []v3.IPPool {
	return q.filter(isQualified)
}

// selecting returns the pools that pass every rule except allowed use. Affine blocks from these pools are kept even
// when this request can't allocate from them.
func (q poolQualification) selecting() []v3.IPPool {
	return q.filter(isSelecting)
}

// filter returns the pools whose rejection reason satisfies keep, in candidate order.
func (q poolQualification) filter(keep func(rejectReason) bool) []v3.IPPool {
	var pools []v3.IPPool
	for _, c := range q.candidates {
		if keep(c.reason) {
			pools = append(pools, c.pool)
		}
	}
	return pools
}

// any reports whether some candidate passes keep, without building the pool list.
func (q poolQualification) any(keep func(rejectReason) bool) bool {
	return slices.ContainsFunc(q.candidates, func(c poolCandidate) bool { return keep(c.reason) })
}

// isQualified reports whether a candidate was not rejected.
func isQualified(r rejectReason) bool {
	return r == ""
}

// isSelecting reports whether a candidate was not rejected, or was rejected only for its allowed uses.
func isSelecting(r rejectReason) bool {
	return r == "" || r == rejectUse
}

// checkSelection applies the rules that only automatic selection uses. A pool with no assignment mode is treated as
// Automatic, the default clientv3 stores.
func checkSelection(pool v3.IPPool, req poolRequest) (rejectReason, error) {
	if pool.Spec.AssignmentMode != nil && *pool.Spec.AssignmentMode != v3.Automatic {
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

// checkUse returns rejectUse when the pool's allowed uses, with the default applied, exclude use.
func checkUse(pool v3.IPPool, use v3.IPPoolAllowedUse) rejectReason {
	if !slices.Contains(accounting.AllowedUses(&pool), use) {
		return rejectUse
	}
	return ""
}

// qualifyPoolForIP applies the rules for assigning a specific IP. Only allowed uses are checked, and only when the
// caller declares a use.
func qualifyPoolForIP(ip net.IP, pool v3.IPPool, use v3.IPPoolAllowedUse) error {
	allowed := accounting.AllowedUses(&pool)
	if use != "" && !slices.Contains(allowed, use) {
		return fmt.Errorf("IP address %s is in IP pool %q, which is not allowed for use %q (allowedUses: %v)", ip, pool.Name, use, allowed)
	}
	return nil
}
