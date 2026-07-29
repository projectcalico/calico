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
	"errors"
	"fmt"
	"sync"
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	calicoclient "github.com/projectcalico/api/pkg/client/clientset_generated/clientset"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/singleflight"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/metadata/metadatainformer"
	"k8s.io/client-go/util/flowcontrol"

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

// The fallback GET path gets its own budget rather than sharing the rest client's (QPS 100 /
// burst 200, set in webhooks/pkg/webhook/command.go). A flood of reads for names that miss the
// informer cache would otherwise take the whole client budget and queue the admission path's
// SubjectAccessReviews behind it. Waiting for a token is bounded by the caller's context, so a
// request that cannot get one in time is denied on its own rather than timing the webhook out.
const (
	fallbackGetQPS   = 25
	fallbackGetBurst = 50
)

// negativeCacheTTL is how long a "policy does not exist" answer is reused, which is what keeps a
// flood of reads for random names off the API server. Well under the AuthorizationConfiguration's
// unauthorizedTTL (30s) on purpose: a not-found becomes NoOpinion, which the API server itself
// caches for that long, so anything larger here would be the dominant term in how long a policy
// created just after a miss keeps being treated as absent.
const negativeCacheTTL = 5 * time.Second

// maxNegativeEntries caps the negative cache so a flood of unique names cannot grow it without
// bound. Past the cap, expired entries are swept and new ones are not recorded: dropping an entry
// costs a GET, not correctness.
const maxNegativeEntries = 4096

// Cache resolves policy names to tiers. It satisfies tierauth.PolicyTierResolver.
type Cache struct {
	factory      metadatainformer.SharedInformerFactory
	informers    map[string]informers.GenericInformer
	calicoClient calicoclient.Interface

	// fallbackLimiter bounds the rate of live GETs. See fallbackGetQPS.
	fallbackLimiter flowcontrol.RateLimiter

	// getGroup collapses concurrent identical lookups into one GET, so that N simultaneous
	// reads of the same uncached policy cost one round trip rather than N.
	getGroup singleflight.Group

	// notFound records recent ErrPolicyNotFound answers. See negativeCacheTTL.
	notFoundMu sync.Mutex
	notFound   map[string]time.Time
}

var _ tierauth.PolicyTierResolver = &Cache{}

// New returns a Cache watching metadata for every tiered policy resource. calicoClient is
// used only for the fallback GET when a policy carries no tier label.
func New(metadataClient metadata.Interface, calicoClient calicoclient.Interface, resync time.Duration) *Cache {
	factory := metadatainformer.NewFilteredSharedInformerFactory(metadataClient, resync, metav1.NamespaceAll, nil)

	c := &Cache{
		factory:         factory,
		informers:       make(map[string]informers.GenericInformer, len(policyGVRs)),
		calicoClient:    calicoClient,
		fallbackLimiter: flowcontrol.NewTokenBucketRateLimiter(fallbackGetQPS, fallbackGetBurst),
		notFound:        make(map[string]time.Time),
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

	metrics.CacheInitialSyncSeconds.Set(float64(time.Now().Unix()))
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
		logrus.WithError(err).WithFields(logrus.Fields{
			"resource":  resource,
			"namespace": namespace,
			"name":      name,
		}).Debug("Policy not in cache, falling back to a GET")
		return c.fallbackGet(ctx, resource, namespace, name, "miss")
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
	return c.fallbackGet(ctx, resource, namespace, name, "unlabeled")
}

// fallbackGet resolves a tier from the API server, behind the negative cache, the rate limiter
// and the in-flight collapser. reason is the metric label describing why the GET was needed.
func (c *Cache) fallbackGet(ctx context.Context, resource, namespace, name, reason string) (string, error) {
	key := resource + "/" + namespace + "/" + name

	if c.recentlyNotFound(key) {
		return "", tierauth.ErrPolicyNotFound
	}

	// Concurrent readers of the same uncached policy share one GET. The leader's context
	// bounds it, so a follower can be handed the leader's context error; that denies the
	// follower, which is the fail-closed direction.
	tier, err, _ := c.getGroup.Do(key, func() (any, error) {
		if err := c.fallbackLimiter.Wait(ctx); err != nil {
			return "", fmt.Errorf("waiting for a policy GET token: %w", err)
		}
		metrics.CacheFallbackGetsTotal.WithLabelValues(resource, reason).Inc()
		return c.tierFromLiveGet(ctx, resource, namespace, name)
	})
	if errors.Is(err, tierauth.ErrPolicyNotFound) {
		c.recordNotFound(key)
	}
	if err != nil {
		return "", err
	}
	return tier.(string), nil
}

// recentlyNotFound reports whether this policy was found to be absent within negativeCacheTTL.
func (c *Cache) recentlyNotFound(key string) bool {
	c.notFoundMu.Lock()
	defer c.notFoundMu.Unlock()

	at, ok := c.notFound[key]
	if !ok {
		return false
	}
	if time.Since(at) >= negativeCacheTTL {
		delete(c.notFound, key)
		return false
	}
	return true
}

func (c *Cache) recordNotFound(key string) {
	c.notFoundMu.Lock()
	defer c.notFoundMu.Unlock()

	if len(c.notFound) >= maxNegativeEntries {
		for k, at := range c.notFound {
			if time.Since(at) >= negativeCacheTTL {
				delete(c.notFound, k)
			}
		}
		if len(c.notFound) >= maxNegativeEntries {
			return
		}
	}
	c.notFound[key] = time.Now()
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
