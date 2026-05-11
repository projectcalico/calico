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

package globalpolicy

import (
	"context"
	"errors"
	"testing"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metainternalversion "k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
)

type denyAllAuthorizer struct{}

func (denyAllAuthorizer) AuthorizeTierOperation(_ context.Context, policyName, _ string) error {
	return k8serrors.NewForbidden(v3.Resource("globalnetworkpolicies"), policyName, errors.New("denied"))
}

type stubLister struct{}

func (stubLister) ListTiers() ([]*v3.Tier, error) {
	return []*v3.Tier{{ObjectMeta: metav1.ObjectMeta{Name: "default"}}}, nil
}
func (stubLister) ListUISettingsGroups() ([]*v3.UISettingsGroup, error) { return nil, nil }
func (stubLister) ListManagedClusters() ([]*v3.ManagedCluster, error)   { return nil, nil }

func deleteCollectionContext() context.Context {
	ctx := genericapirequest.NewContext()
	ctx = genericapirequest.WithUser(ctx, &user.DefaultInfo{Name: "low-priv"})
	ctx = genericapirequest.WithRequestInfo(ctx, &genericapirequest.RequestInfo{
		IsResourceRequest: true,
		Verb:              "deletecollection",
		APIGroup:          "projectcalico.org",
		APIVersion:        "v3",
		Resource:          "globalnetworkpolicies",
		Path:              "/apis/projectcalico.org/v3/globalnetworkpolicies",
	})
	return ctx
}

// Regression test: bulk delete on cluster-scoped GlobalNetworkPolicy must
// fail with Forbidden when the caller has no tier authorization, rather
// than falling through to the embedded Store and silently wiping policies
// in other tiers. Embedded *registry.Store is intentionally left nil.
func TestDeleteCollection_DeniesWhenNoTiersAuthorized(t *testing.T) {
	r := &REST{
		CalicoResourceLister: stubLister{},
		authorizer:           denyAllAuthorizer{},
	}

	_, err := r.DeleteCollection(deleteCollectionContext(), nil, &metav1.DeleteOptions{}, &metainternalversion.ListOptions{})
	if err == nil {
		t.Fatalf("DeleteCollection succeeded for unauthorized caller; expected Forbidden")
	}
	if !k8serrors.IsForbidden(err) {
		t.Fatalf("expected Forbidden error, got %v", err)
	}
}
