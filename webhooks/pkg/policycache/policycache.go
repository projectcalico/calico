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

// Package policycache answers "which tier is this policy in" from a metadata-only
// informer over the tiered policy resources. The projectcalico.org/tier label already
// carries the answer, so there is no need to cache policy bodies.
package policycache

import (
	"context"
	"fmt"
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	calicoclient "github.com/projectcalico/api/pkg/client/clientset_generated/clientset"
	"github.com/sirupsen/logrus"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/metadata/metadatainformer"

	"github.com/projectcalico/calico/libcalico-go/lib/names"
	"github.com/projectcalico/calico/webhooks/pkg/metrics"
	"github.com/projectcalico/calico/webhooks/pkg/tierauth"
)

// policyGVRs maps each tiered policy resource to the GroupVersionResource to watch.
var policyGVRs = map[string]schema.GroupVersionResource{
	"networkpolicies":                 v3.SchemeGroupVersion.WithResource("networkpolicies"),
	"globalnetworkpolicies":           v3.SchemeGroupVersion.WithResource("globalnetworkpolicies"),
	"stagednetworkpolicies":           v3.SchemeGroupVersion.WithResource("stagednetworkpolicies"),
	"stagedglobalnetworkpolicies":     v3.SchemeGroupVersion.WithResource("stagedglobalnetworkpolicies"),
	"stagedkubernetesnetworkpolicies": v3.SchemeGroupVersion.WithResource("stagedkubernetesnetworkpolicies"),
}

// Cache resolves policy names to tiers. It satisfies tierauth.PolicyTierResolver.
type Cache struct {
	factory      metadatainformer.SharedInformerFactory
	informers    map[string]informers.GenericInformer
	calicoClient calicoclient.Interface
}

var _ tierauth.PolicyTierResolver = &Cache{}

// New returns a Cache watching metadata for every tiered policy resource. calicoClient is
// used only for the fallback GET when a policy carries no tier label.
func New(metadataClient metadata.Interface, calicoClient calicoclient.Interface, resync time.Duration) *Cache {
	factory := metadatainformer.NewFilteredSharedInformerFactory(metadataClient, resync, metav1.NamespaceAll, nil)

	c := &Cache{
		factory:      factory,
		informers:    make(map[string]informers.GenericInformer, len(policyGVRs)),
		calicoClient: calicoClient,
	}
	for resource, gvr := range policyGVRs {
		c.informers[resource] = factory.ForResource(gvr)
	}
	return c
}

// Start starts every informer and blocks until all caches have synced, or ctx is done.
// Readiness must gate on HasSynced: serving before sync would deny reads that should pass.
func (c *Cache) Start(ctx context.Context) error {
	c.factory.Start(ctx.Done())

	for resource, inf := range c.informers {
		if !cacheSyncWithContext(ctx, inf) {
			return fmt.Errorf("timed out waiting for the %s cache to sync", resource)
		}
	}

	metrics.CacheLastSyncSeconds.Set(float64(time.Now().Unix()))
	logrus.WithField("resources", len(c.informers)).Info("Policy tier cache synced")
	return nil
}

func cacheSyncWithContext(ctx context.Context, inf informers.GenericInformer) bool {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if inf.Informer().HasSynced() {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
		}
	}
}

// HasSynced reports whether every informer has completed its initial list. Safe to call
// concurrently with Start: sharedIndexInformer.HasSynced() is a select on a channel that
// Run closes, and c.informers is populated once in New and never written again.
func (c *Cache) HasSynced() bool {
	for _, inf := range c.informers {
		if !inf.Informer().HasSynced() {
			return false
		}
	}
	return true
}

// TierForPolicy returns the tier of the named policy, or tierauth.ErrPolicyNotFound.
func (c *Cache) TierForPolicy(ctx context.Context, resource, namespace, name string) (string, error) {
	inf, ok := c.informers[resource]
	if !ok {
		return "", fmt.Errorf("%s is not a tiered policy resource", resource)
	}

	var obj any
	var err error
	if namespace == "" {
		obj, err = inf.Lister().Get(name)
	} else {
		obj, err = inf.Lister().ByNamespace(namespace).Get(name)
	}
	if err != nil {
		// Any lister error means the object is not in the cache. Fall back to a live GET
		// rather than denying, so a read-after-write does not produce a spurious Forbidden.
		metrics.CacheFallbackGetsTotal.WithLabelValues(resource, "miss").Inc()
		logrus.WithError(err).WithFields(logrus.Fields{
			"resource":  resource,
			"namespace": namespace,
			"name":      name,
		}).Debug("Policy not in cache, falling back to a GET")
		return c.tierFromLiveGet(ctx, resource, namespace, name)
	}

	meta, ok := obj.(*metav1.PartialObjectMetadata)
	if !ok {
		return "", fmt.Errorf("cache returned %T for %s/%s, expected PartialObjectMetadata", obj, namespace, name)
	}
	if tier := meta.Labels[v3.LabelTier]; tier != "" {
		return tier, nil
	}

	// Policies created before the tier-label MutatingAdmissionPolicy was installed carry no
	// label, so read spec.tier directly.
	metrics.CacheFallbackGetsTotal.WithLabelValues(resource, "unlabeled").Inc()
	return c.tierFromLiveGet(ctx, resource, namespace, name)
}

// tierFromLiveGet reads spec.tier straight from the API server. Used on a cache miss and
// when a cached policy carries no tier label.
func (c *Cache) tierFromLiveGet(ctx context.Context, resource, namespace, name string) (string, error) {
	v3Client := c.calicoClient.ProjectcalicoV3()
	opts := metav1.GetOptions{}

	switch resource {
	case "networkpolicies":
		policy, err := v3Client.NetworkPolicies(namespace).Get(ctx, name, opts)
		if err != nil {
			return "", wrapGetError(err)
		}
		return tierOrDefault(policy.Spec.Tier), nil
	case "globalnetworkpolicies":
		policy, err := v3Client.GlobalNetworkPolicies().Get(ctx, name, opts)
		if err != nil {
			return "", wrapGetError(err)
		}
		return tierOrDefault(policy.Spec.Tier), nil
	case "stagednetworkpolicies":
		policy, err := v3Client.StagedNetworkPolicies(namespace).Get(ctx, name, opts)
		if err != nil {
			return "", wrapGetError(err)
		}
		return tierOrDefault(policy.Spec.Tier), nil
	case "stagedglobalnetworkpolicies":
		policy, err := v3Client.StagedGlobalNetworkPolicies().Get(ctx, name, opts)
		if err != nil {
			return "", wrapGetError(err)
		}
		return tierOrDefault(policy.Spec.Tier), nil
	case "stagedkubernetesnetworkpolicies":
		// StagedKubernetesNetworkPolicy has no Tier field; it is always in the default tier.
		if _, err := v3Client.StagedKubernetesNetworkPolicies(namespace).Get(ctx, name, opts); err != nil {
			return "", wrapGetError(err)
		}
		return names.DefaultTierName, nil
	}

	return "", fmt.Errorf("%s is not a tiered policy resource", resource)
}

// wrapGetError converts a NotFound into ErrPolicyNotFound, so callers can tell "no such
// policy" (let RBAC 404 it) from "lookup failed" (deny, because we are fail-closed).
func wrapGetError(err error) error {
	if k8serrors.IsNotFound(err) {
		return tierauth.ErrPolicyNotFound
	}
	return fmt.Errorf("get policy: %w", err)
}

func tierOrDefault(tier string) string {
	if tier == "" {
		return names.DefaultTierName
	}
	return tier
}
