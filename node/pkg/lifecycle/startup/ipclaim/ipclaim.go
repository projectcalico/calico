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

// Package ipclaim claims a node's detected IP addresses via Kubernetes
// Leases, replacing a full-cluster Node List-and-scan conflict check with an
// O(1) atomic claim per address.
package ipclaim

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	coordinationv1 "k8s.io/api/coordination/v1"
	v1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

// LeaseNamespace is the namespace the IP claim Lease client reads, creates,
// and deletes calico-ip-* Leases in. It is deliberately not kube-system:
// Kubernetes RBAC resourceNames only supports exact literal name lists, and
// the calico-ip-<ip> Lease names are only known at runtime, so a Role can't
// scope this down by name. Sharing kube-system with control-plane
// leader-election Leases (kube-scheduler, kube-controller-manager) would
// mean a bug or compromised calico-node pod -- hostNetwork and privileged,
// running on every node -- could delete or overwrite one of those and force
// an unrelated leader-election flap. calico-system is the namespace
// calico-node's own ServiceAccount and DaemonSet already live in exclusively,
// so scoping the Lease RBAC Role there instead bounds the blast radius to
// calico-node's own resources.
const LeaseNamespace = "calico-system"

// claimRetryAttempts and claimRetryBackoff bound how many times, and how
// long between tries, ClaimNodeIPLease retries a Create that failed for a
// reason other than AlreadyExists (a real conflict, which is never retried)
// before giving up and returning the error to the caller. A mass scale-up or
// fleet reboot -- the exact scenario this package exists to survive -- is
// also when apiserver latency is most likely to be degraded; without a
// retry, a transient timeout on Create is indistinguishable from a real
// conflict, and both terminate node startup. Package-level variables, not
// constants, so tests can shrink claimRetryBackoff instead of sleeping for
// real.
var (
	claimRetryAttempts = 3
	claimRetryBackoff  = 500 * time.Millisecond
)

// retryBackoffWithJitter returns claimRetryBackoff plus up to half of
// claimRetryBackoff again, chosen at random. A mass scale-up or fleet
// reboot -- the scenario this package exists to survive -- is also the
// scenario where many nodes' Create calls are most likely to fail together
// (shared apiserver overload), and a fixed backoff makes them all retry in
// lock-step, reproducing the very burst they're backing off from. Partial
// jitter (rather than full 0..claimRetryBackoff jitter) keeps a floor under
// the sleep so a test that shrinks claimRetryBackoff via withFastRetries can
// still assume a bounded, short-but-nonzero sleep.
func retryBackoffWithJitter() time.Duration {
	if claimRetryBackoff <= 0 {
		return 0
	}
	return claimRetryBackoff + time.Duration(rand.Int63n(int64(claimRetryBackoff)/2+1))
}

// LeaseNameForIP encodes an IP address as a valid Kubernetes object name,
// e.g. "10.0.1.5" -> "calico-ip-10-0-1-5", "fe80::1" -> "calico-ip-fe80--1".
//
// An IPv6 address whose RFC 5952 canonical form ends in the "::"
// zero-compression marker (e.g. the unspecified address "::", or
// "2001:db8:1::") would otherwise produce a name ending in "-", which fails
// Kubernetes' DNS1123-subdomain name validation (names must start and end
// with an alphanumeric character) and makes the Lease Create call fail
// deterministically. Guard only the trailing edge: the "calico-ip-" prefix
// already guarantees the name starts with an alnum character. "z" is
// appended because it never occurs naturally in a lowercased IP's string
// form (which is limited to hex digits, decimal digits, "." and ":"), so it
// can't collide with a genuine address character, and it's only appended
// when the string already ends in "-", so it can't collide between two
// different addresses either -- everything before the trailing hyphen run
// is already the unique, distinguishing part of the name.
func LeaseNameForIP(ip net.IP) string {
	s := strings.ToLower(ip.String())
	s = strings.ReplaceAll(s, ":", "-")
	s = strings.ReplaceAll(s, ".", "-")
	if strings.HasSuffix(s, "-") {
		s += "z"
	}
	return "calico-ip-" + s
}

// ClaimNodeIPLease atomically claims ip for holderNodeName using a
// coordination.k8s.io/v1 Lease named after the IP (see LeaseNameForIP).
// Lease creation is atomic at the API server (an etcd CreateRevision==0
// guard), so two nodes racing to claim the same IP never both succeed: the
// loser gets AlreadyExists, reported here as a conflict.
//
// The Lease carries an OwnerReference to k8sNode so it is garbage-collected
// automatically when the Node object is deleted: the caller does not delete
// its own Lease on shutdown, so a crashed node never leaves the IP wedged --
// the Node's lifecycle, not the caller's process lifecycle, is the source of
// truth for whether a claim is still valid. If k8sNode is nil the claim is
// still made, but without an OwnerReference, so it will not be cleaned up
// automatically.
//
// When the Lease already exists and is already held by holderNodeName, this
// also repairs a stale owner reference: if the Node object was deleted and
// re-registered under the same name (a `kubectl delete node`, a
// cluster-operator/autoscaler action, or a Machine-lifecycle recreate all do
// this -- the name is stable but the UID isn't), the surviving Lease still
// owner-references the old, now-nonexistent UID, and Kubernetes' garbage
// collector will eventually delete it as an orphan out from under a node
// that is still alive and still holds the address. Re-pointing the
// OwnerReferences at the current k8sNode.UID closes that window.
//
// A Create error that isn't AlreadyExists is retried up to claimRetryAttempts
// times with a jittered claimRetryBackoff pause in between (see
// retryBackoffWithJitter): during a mass scale-up or fleet reboot, apiserver
// latency is exactly what's degraded, so a transient timeout is not a
// reliable signal of a real conflict and shouldn't be treated as fatal on
// the first failure. AlreadyExists itself is never retried -- it is already
// a conclusive answer, not a transient condition -- but the follow-up Get it
// triggers can still race: if the Lease that caused AlreadyExists is deleted
// (e.g. its owning Node was deleted and Kubernetes GC reaped it) between our
// Create and this Get, the Get comes back NotFound even though the IP is
// free again, and that specific case is retried like any other transient
// failure instead of being treated as a hard error.
//
// If the Lease is already held by us and its OwnerReferences turn out to be
// stale (see below), a failure to repair that owner reference is logged as a
// warning, not returned as an error: the claim itself already succeeded --
// we already hold HolderIdentity -- so a benign race on the repair Update
// (e.g. a concurrent racer for the same node name during a rolling restart)
// must not fail node startup over what is, at worst, a deferred cleanup that
// can be retried on a later run.
//
// Returns conflict=true (with the current holder's node name) if the Lease is
// already held by a different node.
func ClaimNodeIPLease(ctx context.Context, clientset kubernetes.Interface, k8sNode *v1.Node, holderNodeName string, ip net.IP) (conflict bool, holder string, err error) {
	name := LeaseNameForIP(ip)
	leaseClient := clientset.CoordinationV1().Leases(LeaseNamespace)

	lease := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: LeaseNamespace,
		},
		Spec: coordinationv1.LeaseSpec{
			HolderIdentity: &holderNodeName,
		},
	}
	if k8sNode != nil {
		lease.OwnerReferences = []metav1.OwnerReference{{
			APIVersion: "v1",
			Kind:       "Node",
			Name:       k8sNode.Name,
			UID:        k8sNode.UID,
		}}
	} else {
		log.Warn("No Kubernetes Node object available; IP claim lease will not be owner-referenced for automatic cleanup")
	}

	var lastErr error
	for attempt := 1; attempt <= claimRetryAttempts; attempt++ {
		_, createErr := leaseClient.Create(ctx, lease, metav1.CreateOptions{})
		switch {
		case createErr == nil:
			return false, holderNodeName, nil
		case kerrors.IsAlreadyExists(createErr):
			existing, getErr := leaseClient.Get(ctx, name, metav1.GetOptions{})
			switch {
			case getErr == nil:
				if existing.Spec.HolderIdentity != nil && *existing.Spec.HolderIdentity == holderNodeName {
					// Already held from a prior run (e.g. a restart with no IP
					// change) -- not a conflict. But the same holder name isn't
					// proof that the Lease's OwnerReference still points at a
					// live Node: if k8sNode was deleted and re-created under the
					// same name, existing's OwnerReferences still carries the
					// old UID, and Kubernetes GC will reap the Lease as an
					// orphan out from under us. Repair it here rather than
					// leaving that window open.
					if k8sNode != nil && !hasOwnerUID(existing.OwnerReferences, k8sNode.UID) {
						existing.OwnerReferences = []metav1.OwnerReference{{
							APIVersion: "v1",
							Kind:       "Node",
							Name:       k8sNode.Name,
							UID:        k8sNode.UID,
						}}
						if _, updateErr := leaseClient.Update(ctx, existing, metav1.UpdateOptions{}); updateErr != nil {
							// The claim already succeeded (we hold
							// HolderIdentity); a repair failure -- including a
							// benign Conflict from a concurrent racer -- is
							// not worth failing node startup over. Retried on
							// a later run.
							log.WithError(updateErr).WithFields(log.Fields{"lease": name, "node": k8sNode.Name}).Warn("IP claim lease has a stale owner reference that could not be repaired this run; the claim itself is unaffected")
						} else {
							log.WithFields(log.Fields{"lease": name, "node": k8sNode.Name}).Info("Repaired stale owner reference on IP claim lease after Node recreation")
						}
					}
					return false, holderNodeName, nil
				}
				otherHolder := "unknown"
				if existing.Spec.HolderIdentity != nil {
					otherHolder = *existing.Spec.HolderIdentity
				}
				return true, otherHolder, nil
			case kerrors.IsNotFound(getErr):
				// The Lease that caused AlreadyExists is gone by the time we
				// read it back -- e.g. its owning Node was deleted and
				// Kubernetes GC reaped it in the window between our Create
				// and this Get. The IP is free again, so retry the Create
				// instead of treating this as a hard error.
				lastErr = fmt.Errorf("IP claim lease %s vanished after AlreadyExists: %w", name, getErr)
				if attempt == claimRetryAttempts {
					break
				}
				log.WithError(getErr).Warnf("IP claim lease %s existed on Create but vanished before Get (attempt %d/%d); retrying", name, attempt, claimRetryAttempts)
				select {
				case <-ctx.Done():
					return false, "", fmt.Errorf("failed to create IP claim lease %s: %w", name, ctx.Err())
				case <-time.After(retryBackoffWithJitter()):
				}
			default:
				return false, "", fmt.Errorf("IP %s already claimed and lease %s could not be read: %w", ip, name, getErr)
			}
		default:
			lastErr = createErr
			if attempt == claimRetryAttempts {
				break
			}
			log.WithError(createErr).Warnf("Failed to create IP claim lease %s (attempt %d/%d); retrying", name, attempt, claimRetryAttempts)
			select {
			case <-ctx.Done():
				return false, "", fmt.Errorf("failed to create IP claim lease %s: %w", name, ctx.Err())
			case <-time.After(retryBackoffWithJitter()):
			}
		}
	}
	return false, "", fmt.Errorf("failed to create IP claim lease %s after %d attempts: %w", name, claimRetryAttempts, lastErr)
}

// hasOwnerUID reports whether refs already contains an owner reference with
// the given UID.
func hasOwnerUID(refs []metav1.OwnerReference, uid types.UID) bool {
	for _, ref := range refs {
		if ref.UID == uid {
			return true
		}
	}
	return false
}

// ReleaseNodeIPLease deletes the Lease claiming ip, but only if it is still
// held by holderNodeName.
//
// This matters because the Lease's OwnerReference only cleans it up when the
// Node object itself is deleted -- but a node can change its detected IP
// while its Node object stays alive (e.g. a brief restart that gets a new
// DHCP-assigned address but keeps the same node identity; the pre-Lease
// conflict check already logged a warning for exactly this case rather than
// treating it as an error). When that happens the old IP's Lease is never
// automatically cleaned up, so callers must release it explicitly once
// they've confirmed which address is no longer held.
//
// The caller's belief that it still owns this Lease can be stale: it comes
// from a Get made before the release, and in the meantime the old Node could
// have been deleted (freeing the Lease via its OwnerReference), claimed by a
// different node, and then claimed again by a third -- all while this node
// is acting on outdated information. Deleting by name alone would remove
// whichever Lease happens to have that name when the delete runs, including
// a different node's live claim, defeating the entire point of an atomic
// claim: two nodes would end up sharing one IP, exactly the outage this
// package exists to prevent. So this reads the Lease first and refuses to
// delete it unless HolderIdentity still names holderNodeName, then deletes
// with a UID+ResourceVersion precondition tying the delete to exactly the
// object just read -- if anything replaced the Lease in between, the
// precondition fails and the delete is skipped rather than removing whatever
// is there now.
//
// A NotFound Get, or a precondition failure (Conflict) or NotFound on
// Delete, is not an error: either way, there is nothing of ours left to
// release. Any other error is returned to the caller to log, but is not
// meant to block claiming the new IP -- leaving a stale Lease around a
// little longer is far less harmful than failing node startup over an
// unrelated cleanup hiccup.
func ReleaseNodeIPLease(ctx context.Context, clientset kubernetes.Interface, holderNodeName string, ip net.IP) error {
	name := LeaseNameForIP(ip)
	leaseClient := clientset.CoordinationV1().Leases(LeaseNamespace)

	existing, err := leaseClient.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		if kerrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("failed to read IP claim lease %s before release: %w", name, err)
	}
	if existing.Spec.HolderIdentity == nil || *existing.Spec.HolderIdentity != holderNodeName {
		// Not ours (any more): someone else's live claim now holds this
		// name. Deleting it would be exactly the bug this check exists to
		// avoid, so leave it alone.
		return nil
	}

	err = leaseClient.Delete(ctx, name, metav1.DeleteOptions{
		Preconditions: &metav1.Preconditions{
			UID:             &existing.UID,
			ResourceVersion: &existing.ResourceVersion,
		},
	})
	if err != nil && !kerrors.IsNotFound(err) && !kerrors.IsConflict(err) {
		return fmt.Errorf("failed to release stale IP claim lease %s: %w", name, err)
	}
	return nil
}

// ForceLegacyScanEnvVar is a rollout safety valve: when set to "true", it
// forces callers to use the legacy full-list conflict scan instead of the
// Lease-based claim in this package, even when a Kubernetes API is otherwise
// available. This lets an operator revert to the pre-Lease behavior without a
// full patch rollback or image rebuild if the Lease-based claim misbehaves in
// production. It is independent of Calico's own DISABLE_NODE_IP_CHECK, which
// skips the conflict check entirely; this instead forces a specific
// implementation of the check to run.
const ForceLegacyScanEnvVar = "FORCE_NODE_IP_CHECK_LEGACY_SCAN"

// ForceLegacyScan reports whether ForceLegacyScanEnvVar is set to "true".
func ForceLegacyScan() bool {
	return os.Getenv(ForceLegacyScanEnvVar) == "true"
}
