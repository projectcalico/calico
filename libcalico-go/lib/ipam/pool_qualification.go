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
	"errors"
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
	claim := newClaim(req)
	named := map[string]bool{}
	for _, rp := range req.requested {
		cidr := rp.Network()
		pool, ok := fitting[cidr.String()]
		if !ok {
			return poolQualification{}, fmt.Errorf("the given pool (%s) does not exist, or is not enabled", cidr.String())
		}
		reason, err := claim.qualify(&pool)
		if err != nil {
			return poolQualification{}, err
		}
		q.add(req.candidate(pool, reason, true))
		named[cidr.String()] = true
	}
	for _, pool := range enabledPools {
		if named[normalizedCIDR(pool)] {
			continue
		}
		reason, err := claim.qualify(&pool)
		if err != nil {
			return poolQualification{}, err
		}
		q.add(req.candidate(pool, reason, false))
	}
	return q, nil
}

// normalizedCIDR is the pool's CIDR in the form fitting is keyed by, or empty when it doesn't parse. IPAM requests
// name pools by CIDR, since the CNI plugin resolves pool names before calling IPAM.
func normalizedCIDR(pool v3.IPPool) string {
	_, cidr, err := net.ParseCIDR(pool.Spec.CIDR)
	if err != nil {
		return ""
	}
	return cidr.String()
}

// qualifyBySelection checks every enabled pool against the assignment mode, the node and namespace selectors, and
// the allowed uses. Unlike named pools, it doesn't check each pool's block size against maxPrefixLen.
func qualifyBySelection(req poolRequest, enabledPools []v3.IPPool) (poolQualification, error) {
	var q poolQualification
	claim := newClaim(req)
	for _, pool := range enabledPools {
		reason, err := claim.qualify(&pool)
		if err != nil {
			return poolQualification{}, err
		}
		q.add(req.candidate(pool, reason, false))
	}
	return q, nil
}

// newClaim builds the claim for a request, naming the pools the request names and matching selectors against the
// request's node and namespace.
func newClaim(r poolRequest) PoolClaim {
	return NewPoolClaim(r.use, r.requested, claimSelectors{node: r.node, namespace: r.namespace})
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

// blocksToRelease returns the affine blocks, out of those the request can't use, that IPAM may release once empty.
func (q poolQualification) blocksToRelease(blocks []net.IPNet) ([]net.IPNet, error) {
	var release []net.IPNet
	for _, block := range blocks {
		kept, err := q.keepsBlock(block)
		if err != nil {
			return nil, err
		}
		if !kept {
			release = append(release, block)
		}
	}
	return release, nil
}

// keepsBlock reports whether IPAM keeps the node's affinity to a block once it is empty. It does when any candidate
// pool covering the block keeps its blocks, even if an overlapping pool skips the node, and when no candidate covers
// it.
func (q poolQualification) keepsBlock(block net.IPNet) (bool, error) {
	covered := false
	for _, c := range q.candidates {
		_, cidr, err := net.ParseCIDR(c.pool.Spec.CIDR)
		if err != nil {
			return false, err
		}
		if !cidr.Contains(block.IP) {
			continue
		}
		if c.keepsBlocks() {
			return true, nil
		}
		covered = true
	}
	return !covered, nil
}

// nodeKeepsBlock reports whether a node keeps its affinity to an empty block when no request is behind the check,
// as after IPs are released. It applies the keepsBlock rule to every enabled pool. The candidates it builds carry no
// rejection reasons, so they stay inside this function rather than being returned as a poolQualification.
func nodeKeepsBlock(node internalapi.Node, enabledPools []v3.IPPool, block net.IPNet) (bool, error) {
	req := poolRequest{node: node}
	var q poolQualification
	for _, pool := range enabledPools {
		q.candidates = append(q.candidates, req.candidate(pool, "", false))
	}
	return q.keepsBlock(block)
}

// keepsBlocks reports whether IPAM keeps the node's affine blocks in the candidate's pool: the request named it, or
// its node selector picks the node.
func (c poolCandidate) keepsBlocks() bool {
	return c.requested || c.selectsNode
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

// PoolClaim holds the parts of an address request that decide which IP pools it may use: the use it asks for,
// the pools it names, and whether each pool's selectors match the requesting node and namespace. IPAM picks
// pools with MayUse, so code that must agree with that choice, such as a report of which nodes are at their block
// limit, can call it too.
type PoolClaim struct {
	use v3.IPPoolAllowedUse

	// pools holds the normalized CIDRs of the pools the claim names, keyed by IP version.
	pools     map[int]map[string]bool
	selectors PoolSelectors
}

// errClaimWithoutSelectors is returned when a claim has no selectors to choose a pool with, because it names no pool
// in that pool's IP family.
var errClaimWithoutSelectors = errors.New("pool claim names no pool in the pool's IP family and has no selectors")

// NewPoolClaim builds a claim for an address request asking for use. pools must be CIDRs that ResolvePools returned,
// and may span both IP families. Named pools apply per family, as AutoAssign applies IPv4Pools and IPv6Pools: in a
// family where the claim names pools it may use only those, and in a family where it names none it chooses by
// selectors. selectors may be nil when no pool passed to MayUse is in a family the claim names no pool in.
func NewPoolClaim(use v3.IPPoolAllowedUse, pools []net.IPNet, selectors PoolSelectors) PoolClaim {
	named := map[int]map[string]bool{}
	for _, p := range pools {
		cidr := p.Network()
		if named[cidr.Version()] == nil {
			named[cidr.Version()] = map[string]bool{}
		}
		named[cidr.Version()][cidr.String()] = true
	}
	return PoolClaim{use: use, pools: named, selectors: selectors}
}

// ResolvePools turns pool names and CIDRs, the forms the CNI plugin accepts, into the CIDRs of IP version version
// that NewPoolClaim takes. Pass every IP pool, as the CNI plugin does, so a disabled pool's name still resolves. An
// entry that parses as a CIDR must match a pool's network in any form; any other entry must be a pool's name. An
// entry that matches no pool, or a pool of the other family, is an error.
func ResolvePools(pools []v3.IPPool, entries []string, version int) ([]net.IPNet, error) {
	resolved := make([]net.IPNet, 0, len(entries))
	for _, entry := range entries {
		cidr, err := resolvePool(pools, entry)
		if err != nil {
			return nil, err
		}
		if cidr.Version() != version {
			return nil, fmt.Errorf("IP pool %q is not an IPv%d pool", entry, version)
		}
		resolved = append(resolved, cidr)
	}
	return resolved, nil
}

// resolvePool returns the CIDR of the pool an entry names, by CIDR or by name.
func resolvePool(pools []v3.IPPool, entry string) (net.IPNet, error) {
	_, entryCIDR, cidrErr := net.ParseCIDR(entry)
	for _, pool := range pools {
		_, poolCIDR, err := net.ParseCIDR(pool.Spec.CIDR)
		if err != nil {
			return net.IPNet{}, fmt.Errorf("pool %s has invalid CIDR %s: %w", pool.Name, pool.Spec.CIDR, err)
		}
		if cidrErr == nil && poolCIDR.String() == entryCIDR.String() {
			return *poolCIDR, nil
		}
		if cidrErr != nil && entry != "" && pool.Name == entry {
			return *poolCIDR, nil
		}
	}
	return net.IPNet{}, fmt.Errorf("no IP pool has name or CIDR %q", entry)
}

// PoolSelectors reports whether an IP pool's node and namespace selectors match a claim's node and namespace. IPAM
// parses each selector per claim; a caller that keeps parsed selectors can answer from those instead.
type PoolSelectors interface {
	SelectsNode(pool *v3.IPPool) (bool, error)
	SelectsNamespace(pool *v3.IPPool) (bool, error)
}

// MayUse reports whether the claim may draw addresses from the pool, claiming blocks in it as needed. The node's
// blocks in the pools a claim may use are what IPAM counts against maxBlocksPerHost for that claim. Pass pools as
// GetEnabledPools returns them, since IPAM never offers a disabled pool, or one masked by an overlapping allocatable
// pool. It returns false whenever it returns an error.
func (c PoolClaim) MayUse(pool *v3.IPPool) (bool, error) {
	reason, err := c.qualify(pool)
	return err == nil && reason == "", err
}

// qualify checks the pool against the claim, returning why the claim may not use it, or empty when it may.
func (c PoolClaim) qualify(pool *v3.IPPool) (rejectReason, error) {
	_, cidr, err := net.ParseCIDR(pool.Spec.CIDR)
	if err != nil {
		return "", fmt.Errorf("pool %s has invalid CIDR %s: %w", pool.Name, pool.Spec.CIDR, err)
	}
	if named := c.pools[cidr.Version()]; len(named) > 0 {
		if !named[cidr.String()] {
			return rejectNotRequested, nil
		}
	} else {
		if c.selectors == nil {
			return "", errClaimWithoutSelectors
		}
		reason, err := c.checkSelection(pool)
		if reason != "" || err != nil {
			return reason, err
		}
	}
	return checkUse(*pool, c.use), nil
}

// checkSelection applies the rules that only a claim naming no pool uses. A pool with no assignment mode is treated
// as Automatic, the default clientv3 stores.
func (c PoolClaim) checkSelection(pool *v3.IPPool) (rejectReason, error) {
	if pool.Spec.AssignmentMode != nil && *pool.Spec.AssignmentMode != v3.Automatic {
		return rejectAssignmentMode, nil
	}

	nodeMatches, err := c.selectors.SelectsNode(pool)
	if err != nil {
		log.WithError(err).WithField("pool", pool).Error("failed to determine if node matches pool")
		return "", err
	}
	if !nodeMatches {
		return rejectNodeSelector, nil
	}

	namespaceMatches, err := c.selectors.SelectsNamespace(pool)
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
