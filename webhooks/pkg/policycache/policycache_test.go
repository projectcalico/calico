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

package policycache

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	fakecalicoclient "github.com/projectcalico/api/pkg/client/clientset_generated/clientset/fake"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	metadatafake "k8s.io/client-go/metadata/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/util/flowcontrol"

	"github.com/projectcalico/calico/libcalico-go/lib/names"
	"github.com/projectcalico/calico/webhooks/pkg/metrics"
	"github.com/projectcalico/calico/webhooks/pkg/tierauth"
)

func namespacedPolicyMeta(namespace, name, tier string) *metav1.PartialObjectMetadata {
	return &metav1.PartialObjectMetadata{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "projectcalico.org/v3",
			Kind:       "NetworkPolicy",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			Labels:    map[string]string{v3.LabelTier: tier},
		},
	}
}

func clusterScopedPolicyMeta(name, tier string) *metav1.PartialObjectMetadata {
	return &metav1.PartialObjectMetadata{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "projectcalico.org/v3",
			Kind:       "GlobalNetworkPolicy",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: map[string]string{v3.LabelTier: tier},
		},
	}
}

func startCache(t *testing.T, objs ...runtime.Object) *Cache {
	t.Helper()

	scheme := metadatafake.NewTestScheme()
	require.NoError(t, metav1.AddMetaToScheme(scheme))
	metadataClient := metadatafake.NewSimpleMetadataClient(scheme, objs...)

	c := New(metadataClient, fakecalicoclient.NewSimpleClientset(), time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	c.Start(ctx)
	require.NoError(t, c.WaitForSync(ctx))
	require.True(t, c.HasSynced())

	return c
}

func TestTierForPolicyFromLabel(t *testing.T) {
	c := startCache(t, namespacedPolicyMeta("ns1", "deny-external", "production"))

	tier, err := c.TierForPolicy(context.Background(), "networkpolicies", "ns1", "deny-external")

	require.NoError(t, err)
	assert.Equal(t, "production", tier)
}

func TestTierForPolicyNotFound(t *testing.T) {
	c := startCache(t)

	_, err := c.TierForPolicy(context.Background(), "networkpolicies", "ns1", "missing")

	assert.True(t, errors.Is(err, tierauth.ErrPolicyNotFound), "got %v", err)
}

func TestTierForPolicyUnknownResource(t *testing.T) {
	c := startCache(t)

	_, err := c.TierForPolicy(context.Background(), "hostendpoints", "ns1", "anything")

	require.Error(t, err)
	assert.False(t, errors.Is(err, tierauth.ErrPolicyNotFound), "an unknown resource is a caller bug, not a missing policy")
}

func TestTierForPolicyFallsBackWhenLabelMissing(t *testing.T) {
	metrics.CacheFallbackGetsTotal.Reset()

	meta := namespacedPolicyMeta("ns1", "unlabeled", "")
	delete(meta.Labels, v3.LabelTier)

	scheme := metadatafake.NewTestScheme()
	require.NoError(t, metav1.AddMetaToScheme(scheme))
	metadataClient := metadatafake.NewSimpleMetadataClient(scheme, meta)

	calicoClient := fakecalicoclient.NewSimpleClientset(&v3.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: "unlabeled"},
		Spec:       v3.NetworkPolicySpec{Tier: "production"},
	})

	c := New(metadataClient, calicoClient, time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	c.Start(ctx)
	require.NoError(t, c.WaitForSync(ctx))

	tier, err := c.TierForPolicy(ctx, "networkpolicies", "ns1", "unlabeled")

	require.NoError(t, err)
	assert.Equal(t, "production", tier, "a policy predating the tier-label MutatingAdmissionPolicy must still resolve")
	assert.Equal(
		t,
		1.0,
		testutil.ToFloat64(metrics.CacheFallbackGetsTotal.WithLabelValues("networkpolicies", "unlabeled")),
		"an unlabeled policy must be counted under the unlabeled reason, not miss",
	)
}

func TestTierForPolicyClusterScopedFromLabel(t *testing.T) {
	c := startCache(t, clusterScopedPolicyMeta("deny-external", "production"))

	tier, err := c.TierForPolicy(context.Background(), "globalnetworkpolicies", "", "deny-external")

	require.NoError(t, err)
	assert.Equal(t, "production", tier)
}

func TestTierForPolicyCacheMissFallsBackToLiveTier(t *testing.T) {
	metrics.CacheFallbackGetsTotal.Reset()

	calicoClient := fakecalicoclient.NewSimpleClientset(&v3.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: "just-created"},
		Spec:       v3.NetworkPolicySpec{Tier: "production"},
	})

	scheme := metadatafake.NewTestScheme()
	require.NoError(t, metav1.AddMetaToScheme(scheme))
	c := New(metadatafake.NewSimpleMetadataClient(scheme), calicoClient, time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	c.Start(ctx)
	require.NoError(t, c.WaitForSync(ctx))

	// The informer's list is empty, so this must come from the live GET, not the cache.
	tier, err := c.TierForPolicy(ctx, "networkpolicies", "ns1", "just-created")

	require.NoError(t, err)
	assert.Equal(t, "production", tier, "a read-after-write must resolve via the live GET, not deny on a cache miss")
	assert.Equal(
		t,
		1.0,
		testutil.ToFloat64(metrics.CacheFallbackGetsTotal.WithLabelValues("networkpolicies", "miss")),
		"a cache miss must be counted under the miss reason, not unlabeled",
	)
}

func TestTierForPolicyLookupFailureIsFailClosed(t *testing.T) {
	c := startCache(t)

	fakeClient, ok := c.calicoClient.(*fakecalicoclient.Clientset)
	require.True(t, ok)
	fakeClient.PrependReactor("get", "networkpolicies", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, k8serrors.NewInternalError(errors.New("etcd unavailable"))
	})

	_, err := c.TierForPolicy(context.Background(), "networkpolicies", "ns1", "anything")

	require.Error(t, err)
	assert.False(t, errors.Is(err, tierauth.ErrPolicyNotFound), "a lookup failure must deny, not be mistaken for a missing policy")
}

func TestTierForPolicyStagedKubernetesNetworkPolicyIsAlwaysDefaultTier(t *testing.T) {
	calicoClient := fakecalicoclient.NewSimpleClientset(&v3.StagedKubernetesNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: "staged"},
	})

	scheme := metadatafake.NewTestScheme()
	require.NoError(t, metav1.AddMetaToScheme(scheme))
	c := New(metadatafake.NewSimpleMetadataClient(scheme), calicoClient, time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	c.Start(ctx)
	require.NoError(t, c.WaitForSync(ctx))

	tier, err := c.TierForPolicy(ctx, "stagedkubernetesnetworkpolicies", "ns1", "staged")

	require.NoError(t, err)
	assert.Equal(t, names.DefaultTierName, tier, "StagedKubernetesNetworkPolicy has no Tier field, so it is always in the default tier")
}

func TestTierOrDefaultMapsEmptyTierToDefault(t *testing.T) {
	assert.Equal(t, names.DefaultTierName, tierOrDefault(""))
	assert.Equal(t, "production", tierOrDefault("production"))
}

func TestHasSyncedFalseBeforeStart(t *testing.T) {
	scheme := metadatafake.NewTestScheme()
	require.NoError(t, metav1.AddMetaToScheme(scheme))

	c := New(metadatafake.NewSimpleMetadataClient(scheme), fakecalicoclient.NewSimpleClientset(), time.Minute)

	assert.False(t, c.HasSynced(), "readiness must not report ready before informers sync")
}

var _ tierauth.PolicyTierResolver = &Cache{}

// countingCalicoClient returns a fake Calico clientset that counts GETs of networkpolicies and,
// if block is non-nil, holds each GET until that channel is closed.
func countingCalicoClient(t *testing.T, block chan struct{}, objs ...runtime.Object) (*fakecalicoclient.Clientset, *atomic.Int64) {
	t.Helper()

	var gets atomic.Int64
	client := fakecalicoclient.NewSimpleClientset(objs...)
	client.PrependReactor("get", "networkpolicies", func(k8stesting.Action) (bool, runtime.Object, error) {
		gets.Add(1)
		if block != nil {
			<-block
		}
		// Fall through to the object tracker, which answers with the object or a NotFound.
		return false, nil, nil
	})
	return client, &gets
}

func TestConcurrentIdenticalLookupsShareOneGet(t *testing.T) {
	block := make(chan struct{})
	calicoClient, gets := countingCalicoClient(t, block, &v3.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: "uncached"},
		Spec:       v3.NetworkPolicySpec{Tier: "production"},
	})

	scheme := metadatafake.NewTestScheme()
	require.NoError(t, metav1.AddMetaToScheme(scheme))
	c := New(metadatafake.NewSimpleMetadataClient(scheme), calicoClient, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	c.Start(ctx)
	require.NoError(t, c.WaitForSync(ctx))

	const readers = 8
	tiers := make(chan string, readers)
	errs := make(chan error, readers)
	for range readers {
		go func() {
			tier, err := c.TierForPolicy(ctx, "networkpolicies", "ns1", "uncached")
			tiers <- tier
			errs <- err
		}()
	}

	// The first GET is held open, so every reader that has started is parked behind it rather
	// than issuing its own.
	require.Eventually(t, func() bool { return gets.Load() == 1 }, 10*time.Second, 10*time.Millisecond)
	time.Sleep(200 * time.Millisecond)
	close(block)

	for range readers {
		require.NoError(t, <-errs)
		assert.Equal(t, "production", <-tiers)
	}
	assert.Equal(t, int64(1), gets.Load(), "concurrent reads of the same uncached policy must collapse into one GET")
}

func TestRepeatedMissesForTheSameNameDoNotGetEveryTime(t *testing.T) {
	calicoClient, gets := countingCalicoClient(t, nil)

	scheme := metadatafake.NewTestScheme()
	require.NoError(t, metav1.AddMetaToScheme(scheme))
	c := New(metadatafake.NewSimpleMetadataClient(scheme), calicoClient, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	c.Start(ctx)
	require.NoError(t, c.WaitForSync(ctx))

	for range 5 {
		_, err := c.TierForPolicy(ctx, "networkpolicies", "ns1", "missing")
		require.True(t, errors.Is(err, tierauth.ErrPolicyNotFound), "got %v", err)
	}

	assert.Equal(t, int64(1), gets.Load(),
		"a flood of reads for the same non-existent name must not produce a GET per read")
}

func TestNegativeCacheEntriesExpire(t *testing.T) {
	c := &Cache{notFound: map[string]time.Time{"k": time.Now().Add(-2 * negativeCacheTTL)}}

	assert.False(t, c.recentlyNotFound("k"), "an entry older than the TTL must not be reused")
	assert.NotContains(t, c.notFound, "k", "an expired entry must be dropped rather than left to accumulate")
}

func TestFallbackGetGivesUpWithTheCallersDeadline(t *testing.T) {
	calicoClient, gets := countingCalicoClient(t, nil)

	scheme := metadatafake.NewTestScheme()
	require.NoError(t, metav1.AddMetaToScheme(scheme))
	c := New(metadatafake.NewSimpleMetadataClient(scheme), calicoClient, 0)
	// One token, then nothing for the rest of the test: the second lookup has to wait.
	c.fallbackLimiter = flowcontrol.NewTokenBucketRateLimiter(0.001, 1)

	startCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	c.Start(startCtx)
	require.NoError(t, c.WaitForSync(startCtx))

	_, err := c.TierForPolicy(startCtx, "networkpolicies", "ns1", "first")
	require.True(t, errors.Is(err, tierauth.ErrPolicyNotFound), "got %v", err)
	require.Equal(t, int64(1), gets.Load())

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = c.TierForPolicy(ctx, "networkpolicies", "ns1", "second")

	require.Error(t, err)
	assert.False(t, errors.Is(err, tierauth.ErrPolicyNotFound),
		"a throttled lookup is a failure to resolve, which denies; it is not a missing policy, which does not")
	assert.Equal(t, int64(1), gets.Load(), "the throttled lookup must not reach the API server")
}

func TestTierForPolicyRefusesUntilSynced(t *testing.T) {
	calicoClient, gets := countingCalicoClient(t, nil)

	scheme := metadatafake.NewTestScheme()
	require.NoError(t, metav1.AddMetaToScheme(scheme))
	// Never started, so nothing has synced. The server listens in this state on purpose, so
	// this is the window /readyz reports 503 for.
	c := New(metadatafake.NewSimpleMetadataClient(scheme), calicoClient, 0)
	require.False(t, c.HasSynced())

	_, err := c.TierForPolicy(context.Background(), "networkpolicies", "ns1", "deny-external")

	require.Error(t, err, "an unsynced cache must not answer; a refusal denies")
	assert.False(t, errors.Is(err, tierauth.ErrPolicyNotFound),
		"unsynced is not 'the policy does not exist': that would hand the request to RBAC")
	assert.Equal(t, int64(0), gets.Load(),
		"an unsynced lister reports every policy as missing, so falling back would put the whole "+
			"cluster's read traffic on live GETs")
	assert.NotEmpty(t, c.unsyncedResources())
}
