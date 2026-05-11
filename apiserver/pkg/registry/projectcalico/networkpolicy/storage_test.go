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

package networkpolicy

import (
	"context"
	"errors"
	"testing"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metainternalversion "k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apiserver/pkg/authentication/user"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
)

// denyAllAuthorizer rejects every tier operation. Used to drive
// DeleteCollection down the EnsureTierSelector "no tiers authorized"
// path so the test never has to invoke the embedded *registry.Store.
type denyAllAuthorizer struct{}

func (denyAllAuthorizer) AuthorizeTierOperation(_ context.Context, policyName, _ string) error {
	return k8serrors.NewForbidden(v3.Resource("networkpolicies"), policyName, errors.New("denied"))
}

// stubLister returns a fixed, non-empty tier set so getAuthorizedTiers
// reaches the "no allowed tiers" branch and produces a Forbidden error
// (rather than the "no tiers exist" no-op branch).
type stubLister struct{}

func (stubLister) ListTiers() ([]*v3.Tier, error) {
	return []*v3.Tier{{ObjectMeta: metav1.ObjectMeta{Name: "default"}}}, nil
}
func (stubLister) ListUISettingsGroups() ([]*v3.UISettingsGroup, error) { return nil, nil }
func (stubLister) ListManagedClusters() ([]*v3.ManagedCluster, error)   { return nil, nil }

func deleteCollectionContext() context.Context {
	ctx := genericapirequest.NewContext()
	ctx = genericapirequest.WithUser(ctx, &user.DefaultInfo{Name: "low-priv"})
	ctx = genericapirequest.WithNamespace(ctx, "ns1")
	ctx = genericapirequest.WithRequestInfo(ctx, &genericapirequest.RequestInfo{
		IsResourceRequest: true,
		Verb:              "deletecollection",
		APIGroup:          "projectcalico.org",
		APIVersion:        "v3",
		Resource:          "networkpolicies",
		Namespace:         "ns1",
		Path:              "/apis/projectcalico.org/v3/namespaces/ns1/networkpolicies",
	})
	return ctx
}

// TestDeleteCollection_DeniesWhenNoTiersAuthorized is the regression test
// for the tier-authz bypass via DeleteCollection. Without the override,
// upstream registry.Store.DeleteCollection would List + per-item Delete
// against the bare embedded Store, skipping tier authorization entirely.
// With the override, EnsureTierSelector rejects the call before any item
// is listed when the caller is not authorized for any tier.
//
// We deliberately leave the embedded *registry.Store nil; the test passes
// by virtue of the override returning Forbidden before any Store method is
// reached. If a future change reverts the override and falls back to the
// embedded DeleteCollection, this test will fail with a nil-pointer panic
// instead of getting back the expected Forbidden error.
func TestDeleteCollection_DeniesWhenNoTiersAuthorized(t *testing.T) {
	r := &REST{
		CalicoResourceLister: stubLister{},
		authorizer:           denyAllAuthorizer{},
	}

	// Use a label selector to mimic a real bulk-delete request.
	req, err := labels.NewRequirement("env", selection.Equals, []string{"prod"})
	if err != nil {
		t.Fatalf("building requirement: %v", err)
	}
	listOpts := &metainternalversion.ListOptions{
		LabelSelector: labels.NewSelector().Add(*req),
	}

	_, err = r.DeleteCollection(deleteCollectionContext(), nil, &metav1.DeleteOptions{}, listOpts)
	if err == nil {
		t.Fatalf("DeleteCollection succeeded for unauthorized caller; expected Forbidden")
	}
	if !k8serrors.IsForbidden(err) {
		t.Fatalf("expected Forbidden error, got %v", err)
	}
}

// TestDeleteCollection_NilListOptions guards the nil-options path. The
// upstream apiserver normally always passes non-nil listOptions, but our
// override defensively handles nil before delegating; this test ensures
// that defensive path also runs the tier check rather than being skipped.
func TestDeleteCollection_NilListOptions(t *testing.T) {
	r := &REST{
		CalicoResourceLister: stubLister{},
		authorizer:           denyAllAuthorizer{},
	}

	_, err := r.DeleteCollection(deleteCollectionContext(), nil, &metav1.DeleteOptions{}, nil)
	if err == nil {
		t.Fatalf("DeleteCollection with nil listOptions succeeded; expected Forbidden")
	}
	if !k8serrors.IsForbidden(err) {
		t.Fatalf("expected Forbidden error, got %v", err)
	}
}
