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
	"testing"
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	fakecalicoclient "github.com/projectcalico/api/pkg/client/clientset_generated/clientset/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	metadatafake "k8s.io/client-go/metadata/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/projectcalico/calico/libcalico-go/lib/names"
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
	require.NoError(t, c.Start(ctx))
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
	require.NoError(t, c.Start(ctx))

	tier, err := c.TierForPolicy(ctx, "networkpolicies", "ns1", "unlabeled")

	require.NoError(t, err)
	assert.Equal(t, "production", tier, "a policy predating the tier-label MutatingAdmissionPolicy must still resolve")
}

func TestTierForPolicyClusterScopedFromLabel(t *testing.T) {
	c := startCache(t, clusterScopedPolicyMeta("deny-external", "production"))

	tier, err := c.TierForPolicy(context.Background(), "globalnetworkpolicies", "", "deny-external")

	require.NoError(t, err)
	assert.Equal(t, "production", tier)
}

func TestTierForPolicyCacheMissFallsBackToLiveTier(t *testing.T) {
	calicoClient := fakecalicoclient.NewSimpleClientset(&v3.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: "just-created"},
		Spec:       v3.NetworkPolicySpec{Tier: "production"},
	})

	scheme := metadatafake.NewTestScheme()
	require.NoError(t, metav1.AddMetaToScheme(scheme))
	c := New(metadatafake.NewSimpleMetadataClient(scheme), calicoClient, time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	require.NoError(t, c.Start(ctx))

	// The informer's list is empty, so this must come from the live GET, not the cache.
	tier, err := c.TierForPolicy(ctx, "networkpolicies", "ns1", "just-created")

	require.NoError(t, err)
	assert.Equal(t, "production", tier, "a read-after-write must resolve via the live GET, not deny on a cache miss")
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
	require.NoError(t, c.Start(ctx))

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
