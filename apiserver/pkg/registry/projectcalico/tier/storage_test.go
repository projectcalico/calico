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

package tier

import (
	"context"
	"errors"
	"testing"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
)

// denyAllAuthorizer rejects every tier operation. Used so the Delete
// override returns Forbidden before any *registry.Store method runs.
type denyAllAuthorizer struct{}

func (denyAllAuthorizer) AuthorizeTierOperation(_ context.Context, name, _ string) error {
	return k8serrors.NewForbidden(v3.Resource("tiers"), name, errors.New("denied"))
}

func tierDeleteContext() context.Context {
	ctx := genericapirequest.NewContext()
	ctx = genericapirequest.WithUser(ctx, &user.DefaultInfo{Name: "low-priv"})
	ctx = genericapirequest.WithRequestInfo(ctx, &genericapirequest.RequestInfo{
		IsResourceRequest: true,
		Verb:              "delete",
		APIGroup:          "projectcalico.org",
		APIVersion:        "v3",
		Resource:          "tiers",
		Name:              "secret-tier",
		Path:              "/apis/projectcalico.org/v3/tiers/secret-tier",
	})
	return ctx
}

// TestDelete_DeniesWhenTierUnauthorized regression-tests the per-item Delete
// tier-authz gate. Without the override, the embedded *registry.Store.Delete
// runs without any tier check and a caller holding bare `delete tiers` RBAC
// can wipe any tier (including emptied ones via the chained attack). The
// embedded Store is intentionally nil here: if a future change drops the
// override and falls through to the embedded method, the test will panic
// instead of silently passing.
func TestDelete_DeniesWhenTierUnauthorized(t *testing.T) {
	r := &REST{authorizer: denyAllAuthorizer{}}

	_, _, err := r.Delete(tierDeleteContext(), "secret-tier", nil, &metav1.DeleteOptions{})
	if err == nil {
		t.Fatalf("Delete succeeded for unauthorized caller; expected Forbidden")
	}
	if !k8serrors.IsForbidden(err) {
		t.Fatalf("expected Forbidden error, got %v", err)
	}
}
