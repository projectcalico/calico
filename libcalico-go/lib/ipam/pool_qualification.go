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
	rejectNotRequested      rejectReason = "not one of the requested pools"
)

// poolCandidate is a pool considered for a request, with the reason it was rejected.
type poolCandidate struct {
	pool   v3.IPPool
	reason rejectReason

	// requested is whether the request named the pool. IPAM never releases a named pool's blocks for the request.
	requested bool

	// selectsNode is whether the pool's node selector picks the request's node, recorded for every enabled pool
	// whatever its reason, since it decides which of the node's affine blocks IPAM may release.
	selectsNode bool
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
		qualification, err = qualifyRequested(req, enabledPools, fitting)
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

// qualifyRequested checks the pools the caller named, in the order named, then records every other enabled pool as
// not requested. A named pool must fit the block size, and only its allowed uses are checked.
func qualifyRequested(req poolRequest, enabledPools []v3.IPPool, fitting map[string]v3.IPPool) (poolQualification, error) {
	var q poolQualification
	claim := req.claim(true)
	named := map[string]bool{}
	for _, rp := range req.requested {
		cidr := rp.Network()
		pool, ok := fitting[cidr.String()]
		if !ok {
			return poolQualification{}, fmt.Errorf("the given pool (%s) does not exist, or is not enabled", cidr.String())
		}
		reason, err := claim.reject(&pool)
		if err != nil {
			return poolQualification{}, err
		}
		q.add(req.candidate(pool, reason, true))
		named[pool.Name] = true
	}
	for _, pool := range enabledPools {
		if !named[pool.Name] {
			q.add(req.candidate(pool, rejectNotRequested, false))
		}
	}
	return q, nil
}

// qualifyBySelection checks every enabled pool against the assignment mode, the node and namespace selectors, and
// the allowed uses. Unlike named pools, it doesn't check each pool's block size against maxPrefixLen.
func qualifyBySelection(req poolRequest, enabledPools []v3.IPPool) (poolQualification, error) {
	var q poolQualification
	claim := req.claim(false)
	for _, pool := range enabledPools {
		reason, err := claim.reject(&pool)
		if err != nil {
			return poolQualification{}, err
		}
		q.add(req.candidate(pool, reason, false))
	}
	return q, nil
}

// claim is the request as a PoolClaim, matching selectors against the request's node and namespace.
func (r poolRequest) claim(named bool) PoolClaim {
	return PoolClaim{Use: r.use, Named: named, Selectors: claimSelectors{node: r.node, namespace: r.namespace}}
}

// candidate builds the request's candidate for a pool, recording whether the pool's node selector picks the node. A
// selector that does not parse counts as picking it, so a bad selector keeps the node's blocks rather than releasing
// them.
func (r poolRequest) candidate(pool v3.IPPool, reason rejectReason, requested bool) poolCandidate {
	selects, err := SelectsNode(pool, r.node)
	if err != nil {
		log.WithError(err).WithField("pool", pool.Name).Error("Failed to determine if node matches pool, keeping its blocks")
		selects = true
	}
	return poolCandidate{pool: pool, reason: reason, requested: requested, selectsNode: selects}
}

// add records a candidate and logs why it was rejected, if it was.
func (q *poolQualification) add(c poolCandidate) {
	if c.reason != "" {
		log.Debugf("IP pool %s rejected: %s", c.pool.Name, c.reason)
	}
	q.candidates = append(q.candidates, c)
}

// qualified returns the pools the request may allocate from.
func (q poolQualification) qualified() []v3.IPPool {
	return q.filter(isQualified)
}

// releasable returns the pools whose blocks affine to the node IPAM may release: those whose node selector skips the
// node, other than pools the request named. A block is released only once it is empty.
func (q poolQualification) releasable() []v3.IPPool {
	var pools []v3.IPPool
	for _, c := range q.candidates {
		if !c.requested && !c.selectsNode {
			pools = append(pools, c.pool)
		}
	}
	return pools
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

// PoolClaim is an address claim as one IP pool sees it: the use it asks for, whether it names its pools, and how the
// pool's selectors match the claiming node and namespace. IPAM decides which pools a claim draws from with Draws, so
// code that must agree with that choice, such as a report of which nodes are at their block limit, can call it too.
type PoolClaim struct {
	Use v3.IPPoolAllowedUse

	// Named is whether the claim names its pools. IPAM uses a named pool whatever its assignment mode and selectors,
	// so only its allowed uses are checked.
	Named bool

	// Selectors is consulted only for a claim that names no pool, and only once the pool's assignment mode passes.
	Selectors PoolSelectors
}

// PoolSelectors reports whether an IP pool's node and namespace selectors match a claim's node and namespace. IPAM
// parses each selector per claim; a caller that keeps parsed selectors can answer from those instead.
type PoolSelectors interface {
	SelectsNode(pool *v3.IPPool) (bool, error)
	SelectsNamespace(pool *v3.IPPool) (bool, error)
}

// Draws reports whether the claim may draw addresses from the pool, claiming blocks in it as needed. The node's blocks
// in the pools a claim draws from are what IPAM counts against maxBlocksPerHost for that claim. The pool must be
// enabled, since IPAM never offers a disabled pool to a claim, named or not.
func (c PoolClaim) Draws(pool *v3.IPPool) (bool, error) {
	reason, err := c.reject(pool)
	return reason == "", err
}

// reject is why the claim may not draw from the pool, or empty when it may.
func (c PoolClaim) reject(pool *v3.IPPool) (rejectReason, error) {
	if !c.Named {
		reason, err := c.checkSelection(pool)
		if reason != "" || err != nil {
			return reason, err
		}
	}
	return checkUse(*pool, c.Use), nil
}

// checkSelection applies the rules that only a claim naming no pool uses. A pool with no assignment mode is treated
// as Automatic, the default clientv3 stores.
func (c PoolClaim) checkSelection(pool *v3.IPPool) (rejectReason, error) {
	if pool.Spec.AssignmentMode != nil && *pool.Spec.AssignmentMode != v3.Automatic {
		return rejectAssignmentMode, nil
	}

	nodeMatches, err := c.Selectors.SelectsNode(pool)
	if err != nil {
		log.WithError(err).WithField("pool", pool).Error("failed to determine if node matches pool")
		return "", err
	}
	if !nodeMatches {
		return rejectNodeSelector, nil
	}

	namespaceMatches, err := c.Selectors.SelectsNamespace(pool)
	if err != nil {
		log.WithError(err).WithField("pool", pool).Error("failed to determine if namespace matches pool")
		return "", err
	}
	if !namespaceMatches {
		return rejectNamespaceSelector, nil
	}
	return "", nil
}

// claimSelectors matches pool selectors against the node and namespace of an IPAM request, parsing each selector.
type claimSelectors struct {
	node      internalapi.Node
	namespace *corev1.Namespace
}

// SelectsNode parses the pool's node selector and matches it against the request's node.
func (s claimSelectors) SelectsNode(pool *v3.IPPool) (bool, error) {
	return SelectsNode(*pool, s.node)
}

// SelectsNamespace parses the pool's namespace selector and matches it against the request's namespace, which some
// requests, such as tunnel addresses, leave nil.
func (s claimSelectors) SelectsNamespace(pool *v3.IPPool) (bool, error) {
	return SelectsNamespace(*pool, s.namespace)
}

// checkUse returns rejectUse when the pool's allowed uses, with the default applied, exclude use.
func checkUse(pool v3.IPPool, use v3.IPPoolAllowedUse) rejectReason {
	if !slices.Contains(accounting.AllowedUses(&pool), use) {
		return rejectUse
	}
	return ""
}

// qualifyPoolForIP applies the rules for assigning a specific IP. Only allowed uses are checked, and only when the
// caller declares a use, since callers that predate the check leave the use empty and must keep working.
func qualifyPoolForIP(ip net.IP, pool v3.IPPool, use v3.IPPoolAllowedUse) error {
	if use != "" && checkUse(pool, use) != "" {
		return fmt.Errorf("IP address %s is in IP pool %q, which is not allowed for use %q (allowedUses: %v)", ip, pool.Name, use, accounting.AllowedUses(&pool))
	}
	return nil
}
