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

package util_test

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metainternalversion "k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apiserver/pkg/authentication/user"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"

	"github.com/projectcalico/calico/apiserver/pkg/rbac"
	"github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/authorizer"
	"github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/util"
)

// fakeTierAuthorizer answers AuthorizeTierOperation against an explicit allow
// list of tier names. Anything not on the list is denied with a Forbidden
// error matching the shape produced by the real authorizer.
type fakeTierAuthorizer struct {
	allowedTiers map[string]bool
}

func (f *fakeTierAuthorizer) AuthorizeTierOperation(ctx context.Context, policyName string, tierName string) error {
	if f.allowedTiers[tierName] {
		return nil
	}
	return k8serrors.NewForbidden(v3.Resource("networkpolicies"), policyName, errors.New("denied by fake authorizer"))
}

// fakeCalicoResourceLister returns a fixed list of tiers and stub-empty
// values for the rest of the CalicoResourceLister surface area.
type fakeCalicoResourceLister struct {
	tiers []string
}

func (f *fakeCalicoResourceLister) ListTiers() ([]*v3.Tier, error) {
	out := make([]*v3.Tier, 0, len(f.tiers))
	for _, t := range f.tiers {
		out = append(out, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: t}})
	}
	return out, nil
}

func (f *fakeCalicoResourceLister) ListUISettingsGroups() ([]*v3.UISettingsGroup, error) {
	return nil, nil
}

func (f *fakeCalicoResourceLister) ListManagedClusters() ([]*v3.ManagedCluster, error) {
	return nil, nil
}

// requestContext returns a context wired up with the user / RequestInfo that
// filters.GetAuthorizerAttributes needs to pull attributes back out.
func requestContext(verb string) context.Context {
	ctx := genericapirequest.NewContext()
	ctx = genericapirequest.WithUser(ctx, &user.DefaultInfo{Name: "tester"})
	ctx = genericapirequest.WithRequestInfo(ctx, &genericapirequest.RequestInfo{
		IsResourceRequest: true,
		Verb:              verb,
		APIGroup:          "projectcalico.org",
		APIVersion:        "v3",
		Resource:          "networkpolicies",
		Namespace:         "ns1",
		Path:              "/apis/projectcalico.org/v3/namespaces/ns1/networkpolicies",
	})
	return ctx
}

// extractTierLabelValues returns the sorted set of tier names captured by a
// projectcalico.org/tier IN(...) requirement on the given selector, or nil if
// no such requirement is present.
func extractTierLabelValues(t *testing.T, sel labels.Selector) []string {
	t.Helper()
	if sel == nil {
		return nil
	}
	reqs, _ := sel.Requirements()
	for _, r := range reqs {
		if r.Key() != "projectcalico.org/tier" {
			continue
		}
		if r.Operator() != selection.In {
			t.Fatalf("expected IN operator on tier requirement, got %v", r.Operator())
		}
		vs := r.Values().List()
		sort.Strings(vs)
		return vs
	}
	return nil
}

func newTierAuth(allowed ...string) authorizer.TierAuthorizer {
	m := make(map[string]bool, len(allowed))
	for _, t := range allowed {
		m[t] = true
	}
	return &fakeTierAuthorizer{allowedTiers: m}
}

func newLister(tiers ...string) rbac.CalicoResourceLister {
	return &fakeCalicoResourceLister{tiers: tiers}
}

func TestEnsureTierSelector_NoSelector_FiltersToAllowedTiers(t *testing.T) {
	// Three tiers exist, user is authorized for two of them. The selector
	// the upstream Store later lists with must restrict to those two — that
	// is precisely what stops a deletecollection bypass: items in tiers the
	// user can't act on are not returned by List, so are not deleted.
	ctx := requestContext("deletecollection")
	opts := &metainternalversion.ListOptions{}

	err := util.EnsureTierSelector(
		ctx, opts,
		newTierAuth("default", "platform"),
		newLister("default", "platform", "security"),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := extractTierLabelValues(t, opts.LabelSelector)
	want := []string{"default", "platform"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("tier label selector = %v, want %v", got, want)
	}
}

func TestEnsureTierSelector_NoSelector_NoTiersAuthorized_Forbidden(t *testing.T) {
	// Tiers exist but user is authorized for none of them — bulk operations
	// must be refused outright rather than silently producing an empty match.
	ctx := requestContext("deletecollection")
	opts := &metainternalversion.ListOptions{}

	err := util.EnsureTierSelector(
		ctx, opts,
		newTierAuth(), // no allowed tiers
		newLister("default", "security"),
	)
	if err == nil {
		t.Fatalf("expected Forbidden error, got nil")
	}
	if !k8serrors.IsForbidden(err) {
		t.Fatalf("expected Forbidden error, got %v", err)
	}
}

func TestEnsureTierSelector_LabelSelectorAuthorizedTier_PassesThrough(t *testing.T) {
	// Caller-supplied tier filter for a tier they are authorized on:
	// EnsureTierSelector must accept it and not return an error.
	ctx := requestContext("deletecollection")
	req, err := labels.NewRequirement("projectcalico.org/tier", selection.Equals, []string{"platform"})
	if err != nil {
		t.Fatalf("building requirement: %v", err)
	}
	opts := &metainternalversion.ListOptions{
		LabelSelector: labels.NewSelector().Add(*req),
	}

	if err := util.EnsureTierSelector(ctx, opts, newTierAuth("platform"), newLister("default", "platform")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEnsureTierSelector_LabelSelectorUnauthorizedTier_Forbidden(t *testing.T) {
	// Caller-supplied tier filter for a tier they are NOT authorized on:
	// must be rejected. This is the spoof case — supplying a label selector
	// for "security" must not let a caller skirt tier authorization.
	ctx := requestContext("deletecollection")
	req, err := labels.NewRequirement("projectcalico.org/tier", selection.Equals, []string{"security"})
	if err != nil {
		t.Fatalf("building requirement: %v", err)
	}
	opts := &metainternalversion.ListOptions{
		LabelSelector: labels.NewSelector().Add(*req),
	}

	err = util.EnsureTierSelector(ctx, opts, newTierAuth("default"), newLister("default", "security"))
	if err == nil {
		t.Fatalf("expected Forbidden error, got nil")
	}
	if !k8serrors.IsForbidden(err) {
		t.Fatalf("expected Forbidden error, got %v", err)
	}
}

func TestEnsureTierSelector_FieldSelectorAuthorizedTier_PassesThrough(t *testing.T) {
	ctx := requestContext("deletecollection")
	opts := &metainternalversion.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("spec.tier", "platform"),
	}
	if err := util.EnsureTierSelector(ctx, opts, newTierAuth("platform"), newLister("default", "platform")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEnsureTierSelector_FieldSelectorUnauthorizedTier_Forbidden(t *testing.T) {
	ctx := requestContext("deletecollection")
	opts := &metainternalversion.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("spec.tier", "security"),
	}
	err := util.EnsureTierSelector(ctx, opts, newTierAuth("default"), newLister("default", "security"))
	if err == nil {
		t.Fatalf("expected Forbidden error, got nil")
	}
	if !k8serrors.IsForbidden(err) {
		t.Fatalf("expected Forbidden, got %v", err)
	}
	// Sanity: the error text identifies a tier-related forbidden, not some other failure mode.
	if !strings.Contains(strings.ToLower(err.Error()), "forbidden") {
		t.Fatalf("error message does not look forbidden-shaped: %v", err)
	}
}
