// Copyright (c) 2024-2026 Tigera, Inc. All rights reserved.

package authorizer_test

import (
	"context"
	"fmt"
	"testing"

	"k8s.io/apiserver/pkg/authentication/user"
	k8sauth "k8s.io/apiserver/pkg/authorization/authorizer"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"

	"github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/authorizer"
)

func getAttributesMapkey(a k8sauth.Attributes) string {
	return fmt.Sprintf("%s/%s", a.GetPath(), a.GetVerb())
}

type testAuth struct {
	t      *testing.T
	lookup map[string]k8sauth.Decision
}

func (t *testAuth) Authorize(ctx context.Context, a k8sauth.Attributes) (authorized k8sauth.Decision, reason string, err error) {
	d, ok := t.lookup[getAttributesMapkey(a)]
	if !ok {
		t.t.Fatalf("Unexpected authz attributes: %v\n%v", a, t.lookup)
	}
	// The authorization code only uses the Decision, so we can return arbitrary reason and error responses.
	return d, "", nil
}

var (
	// Test users and attributes that are used for multiple tests.
	testUser = &user.DefaultInfo{
		Name:   "testuser",
		UID:    "abced",
		Groups: []string{"group1", "group2"},
	}

	getTierAttr = k8sauth.AttributesRecord{
		User:            testUser,
		Verb:            "get",
		Namespace:       "",
		APIGroup:        "projectcalico.org",
		APIVersion:      "v3",
		Resource:        "tiers",
		Subresource:     "",
		Name:            "test-tier",
		ResourceRequest: true,
		Path:            "/apis/projectcalico.org/v3/tiers/test-tier",
	}
)

// createGlobalNetworkPolicyAttr returns the expected RBAC attributes for a GlobalNetworkPolicy.
func createGlobalNetworkPolicyAttr(verb string) k8sauth.Attributes {
	ar := k8sauth.AttributesRecord{
		User:            testUser,
		Verb:            verb,
		APIGroup:        "projectcalico.org",
		APIVersion:      "v3",
		Resource:        "tier.globalnetworkpolicies",
		Name:            "test-tier.test-gnp",
		ResourceRequest: true,
		Path:            "/apis/projectcalico.org/v3/tier.globalnetworkpolicies/test-tier.test-gnp",
	}
	if verb == "list" || verb == "create" {
		ar.Path = "/apis/projectcalico.org/v3/tier.globalnetworkpolicies"
		ar.Name = ""
	}
	return ar
}

// createGlobalNetworkPolicyTierAttr returns the expected attributes for a tier wildcard GlobalNetworkPolicy match.
func createGlobalNetworkPolicyTierAttr(verb string) k8sauth.Attributes {
	return k8sauth.AttributesRecord{
		User:            testUser,
		Verb:            verb,
		APIGroup:        "projectcalico.org",
		APIVersion:      "v3",
		Resource:        "tier.globalnetworkpolicies",
		Name:            "test-tier.*",
		ResourceRequest: true,
		Path:            "/apis/projectcalico.org/v3/tier.globalnetworkpolicies/test-tier.*",
	}
}

// createNetworkPolicyAttr returns the expected RBAC attributes for a NetworkPolicy.
func createNetworkPolicyAttr(verb string) k8sauth.Attributes {
	ar := k8sauth.AttributesRecord{
		User:            testUser,
		Verb:            verb,
		Namespace:       "test-namespace",
		APIGroup:        "projectcalico.org",
		APIVersion:      "v3",
		Resource:        "tier.networkpolicies",
		Name:            "test-tier.test-np",
		ResourceRequest: true,
		Path:            "/apis/projectcalico.org/v3/namespaces/test-namespace/tier.networkpolicies/test-tier.test-np",
	}
	if verb == "list" || verb == "create" {
		ar.Path = "/apis/projectcalico.org/v3/namespaces/test-namespace/tier.networkpolicies"
		ar.Name = ""
	}
	return ar
}

// createNetworkPolicyTierAttr returns the expected attributes for a tier wildcard NetworkPolicy match.
func createNetworkPolicyTierAttr(verb string) k8sauth.Attributes {
	return k8sauth.AttributesRecord{
		User:            testUser,
		Verb:            verb,
		Namespace:       "test-namespace",
		APIGroup:        "projectcalico.org",
		APIVersion:      "v3",
		Resource:        "tier.networkpolicies",
		Name:            "test-tier.*",
		ResourceRequest: true,
		Path:            "/apis/projectcalico.org/v3/namespaces/test-namespace/tier.networkpolicies/test-tier.*",
	}
}

// createGlobalNetworkPolicyContext returns a request context for a GlobalNetworkPolicy.
func createGlobalNetworkPolicyContext(verb string) context.Context {
	ctx := genericapirequest.NewContext()
	ctx = genericapirequest.WithUser(ctx, testUser)
	ri := &genericapirequest.RequestInfo{
		IsResourceRequest: true,
		Path:              "/apis/projectcalico.org/v3/globalnetworkpolicies/test-tier.test-gnp",
		Verb:              verb,
		APIGroup:          "projectcalico.org",
		APIVersion:        "v3",
		Resource:          "globalnetworkpolicies",
		Name:              "test-tier.test-gnp",
	}
	if verb == "list" || verb == "create" {
		ri.Name = ""
		ri.Path = "/apis/projectcalico.org/v3/globalnetworkpolicies"
	}
	ctx = genericapirequest.WithRequestInfo(ctx, ri)
	return ctx
}

// createNetworkPolicyContext returns a request context for a NetworkPolicy.
func createNetworkPolicyContext(verb string) context.Context {
	ctx := genericapirequest.NewContext()
	ctx = genericapirequest.WithUser(ctx, testUser)
	ctx = genericapirequest.WithNamespace(ctx, "test-namespace")
	ri := &genericapirequest.RequestInfo{
		IsResourceRequest: true,
		Path:              "/apis/projectcalico.org/v3/namespaces/test-namespace/networkpolicies/test-tier.test-np",
		Verb:              verb,
		APIGroup:          "projectcalico.org",
		APIVersion:        "v3",
		Resource:          "networkpolicies",
		Namespace:         "test-namespace",
		Name:              "test-tier.test-np",
	}
	if verb == "list" || verb == "create" {
		ri.Name = ""
		ri.Path = "/apis/projectcalico.org/v3/namespaces/test-namespace/networkpolicies"
	}
	ctx = genericapirequest.WithRequestInfo(ctx, ri)
	return ctx
}

func createNetworkPolicyError(verb string, cannotGetTier bool) string {
	msg := "networkpolicies.projectcalico.org "
	if verb != "list" {
		msg += "\"test-tier.test-np\" "
	}
	msg += "is forbidden: User \"testuser\" cannot " + verb +
		" networkpolicies.projectcalico.org in tier \"test-tier\" and namespace \"test-namespace\""
	if cannotGetTier {
		msg += " (user cannot get tier)"
	}
	return msg
}

func createGlobalNetworkPolicyError(verb string, cannotGetTier bool) string {
	msg := "globalnetworkpolicies.projectcalico.org "
	if verb != "list" {
		msg += "\"test-tier.test-gnp\" "
	}
	msg += "is forbidden: User \"testuser\" cannot " + verb +
		" globalnetworkpolicies.projectcalico.org in tier \"test-tier\""
	if cannotGetTier {
		msg += " (user cannot get tier)"
	}
	return msg
}

func TestNetworkPolicyNoTierGet(t *testing.T) {
	ta := &testAuth{t, map[string]k8sauth.Decision{
		getAttributesMapkey(getTierAttr):                           k8sauth.DecisionDeny,
		getAttributesMapkey(createNetworkPolicyAttr("create")):     k8sauth.DecisionAllow,
		getAttributesMapkey(createNetworkPolicyTierAttr("create")): k8sauth.DecisionAllow,
		getAttributesMapkey(createNetworkPolicyAttr("list")):       k8sauth.DecisionAllow,
		getAttributesMapkey(createNetworkPolicyTierAttr("list")):   k8sauth.DecisionAllow,
		getAttributesMapkey(createNetworkPolicyAttr("delete")):     k8sauth.DecisionAllow,
		getAttributesMapkey(createNetworkPolicyTierAttr("delete")): k8sauth.DecisionAllow,
	}}
	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createNetworkPolicyContext("create"), "test-tier.test-np", "test-tier",
	); err == nil {
		t.Fatalf("No error returned creating NetworkPolicy when tier GET not permitted")
	} else if err.Error() != createNetworkPolicyError("create", true) {
		t.Fatalf("Incorrect error message creating NetworkPolicy when tier GET not permitted: %v", err)
	}

	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createNetworkPolicyContext("delete"), "test-tier.test-np", "test-tier",
	); err == nil {
		t.Fatalf("No error returned deleting NetworkPolicy when tier GET not permitted")
	} else if err.Error() != createNetworkPolicyError("delete", true) {
		t.Fatalf("Incorrect error message deleting NetworkPolicy when tier GET not permitted: %v", err)
	}

	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createNetworkPolicyContext("list"), "", "test-tier",
	); err == nil {
		t.Fatalf("No error returned listing NetworkPolicy when tier GET not permitted")
	} else if err.Error() != createNetworkPolicyError("list", true) {
		t.Fatalf("Incorrect error message listing NetworkPolicy when tier GET not permitted: %v", err)
	}
}

func TestGlobalNetworkPolicyNoTierGet(t *testing.T) {
	ta := &testAuth{t, map[string]k8sauth.Decision{
		getAttributesMapkey(getTierAttr):                                 k8sauth.DecisionDeny,
		getAttributesMapkey(createGlobalNetworkPolicyAttr("create")):     k8sauth.DecisionAllow,
		getAttributesMapkey(createGlobalNetworkPolicyTierAttr("create")): k8sauth.DecisionAllow,
		getAttributesMapkey(createGlobalNetworkPolicyAttr("list")):       k8sauth.DecisionAllow,
		getAttributesMapkey(createGlobalNetworkPolicyTierAttr("list")):   k8sauth.DecisionAllow,
		getAttributesMapkey(createGlobalNetworkPolicyAttr("get")):        k8sauth.DecisionAllow,
		getAttributesMapkey(createGlobalNetworkPolicyTierAttr("get")):    k8sauth.DecisionAllow,
	}}
	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createGlobalNetworkPolicyContext("create"), "test-tier.test-gnp", "test-tier",
	); err == nil {
		t.Fatalf("No error returned creating GlobalNetworkPolicy when tier GET not permitted")
	} else if err.Error() != createGlobalNetworkPolicyError("create", true) {
		t.Fatalf("Incorrect error message creating GlobalNetworkPolicy when tier GET not permitted: %v", err)
	}

	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createGlobalNetworkPolicyContext("get"), "test-tier.test-gnp", "test-tier",
	); err == nil {
		t.Fatalf("No error returned getting GlobalNetworkPolicy when tier GET not permitted")
	} else if err.Error() != createGlobalNetworkPolicyError("get", true) {
		t.Fatalf("Incorrect error message getting GlobalNetworkPolicy when tier GET not permitted: %v", err)
	}

	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createGlobalNetworkPolicyContext("list"), "", "test-tier",
	); err == nil {
		t.Fatalf("No error returned listing GlobalNetworkPolicy when tier GET not permitted")
	} else if err.Error() != createGlobalNetworkPolicyError("list", true) {
		t.Fatalf("Incorrect error message listing GlobalNetworkPolicy when tier GET not permitted: %v", err)
	}
}

func TestNetworkPolicyTierWildcard(t *testing.T) {
	ta := &testAuth{t, map[string]k8sauth.Decision{
		getAttributesMapkey(getTierAttr):                           k8sauth.DecisionAllow,
		getAttributesMapkey(createNetworkPolicyAttr("create")):     k8sauth.DecisionDeny,
		getAttributesMapkey(createNetworkPolicyTierAttr("create")): k8sauth.DecisionAllow,
		getAttributesMapkey(createNetworkPolicyAttr("list")):       k8sauth.DecisionDeny,
		getAttributesMapkey(createNetworkPolicyTierAttr("list")):   k8sauth.DecisionAllow,
		getAttributesMapkey(createNetworkPolicyAttr("delete")):     k8sauth.DecisionDeny,
		getAttributesMapkey(createNetworkPolicyTierAttr("delete")): k8sauth.DecisionAllow,
	}}
	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createNetworkPolicyContext("create"), "test-tier.test-np", "test-tier",
	); err != nil {
		t.Fatalf("Error returned creating NetworkPolicy when tier GET and wildcard match permit the request: %v", err)
	}

	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createNetworkPolicyContext("delete"), "test-tier.test-np", "test-tier",
	); err != nil {
		t.Fatalf("Error returned deleting NetworkPolicy when tier GET and wildcard match permit the request: %v", err)
	}

	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createNetworkPolicyContext("list"), "", "test-tier",
	); err != nil {
		t.Fatalf("Error returned listing NetworkPolicy when tier GET and wildcard match permit the request: %v", err)
	}
}

func TestGlobalNetworkPolicyTierWildcard(t *testing.T) {
	ta := &testAuth{t, map[string]k8sauth.Decision{
		getAttributesMapkey(getTierAttr):                                 k8sauth.DecisionAllow,
		getAttributesMapkey(createGlobalNetworkPolicyAttr("create")):     k8sauth.DecisionDeny,
		getAttributesMapkey(createGlobalNetworkPolicyTierAttr("create")): k8sauth.DecisionAllow,
		getAttributesMapkey(createGlobalNetworkPolicyAttr("list")):       k8sauth.DecisionDeny,
		getAttributesMapkey(createGlobalNetworkPolicyTierAttr("list")):   k8sauth.DecisionAllow,
		getAttributesMapkey(createGlobalNetworkPolicyAttr("delete")):     k8sauth.DecisionDeny,
		getAttributesMapkey(createGlobalNetworkPolicyTierAttr("delete")): k8sauth.DecisionAllow,
	}}
	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createGlobalNetworkPolicyContext("create"), "test-tier.test-gnp", "test-tier",
	); err != nil {
		t.Fatalf("Error returned creating GlobalNetworkPolicy when tier GET and wildcard match permit the request: %v", err)
	}

	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createGlobalNetworkPolicyContext("delete"), "test-tier.test-gnp", "test-tier",
	); err != nil {
		t.Fatalf("Error returned deleting GlobalNetworkPolicy when tier GET and wildcard match permit the request: %v", err)
	}

	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createGlobalNetworkPolicyContext("list"), "", "test-tier",
	); err != nil {
		t.Fatalf("Error returned listing GlobalNetworkPolicy when tier GET and wildcard match permit the request: %v", err)
	}
}

func TestNetworkPolicyByName(t *testing.T) {
	ta := &testAuth{t, map[string]k8sauth.Decision{
		getAttributesMapkey(getTierAttr):                           k8sauth.DecisionAllow,
		getAttributesMapkey(createNetworkPolicyAttr("create")):     k8sauth.DecisionAllow,
		getAttributesMapkey(createNetworkPolicyTierAttr("create")): k8sauth.DecisionDeny,
		getAttributesMapkey(createNetworkPolicyAttr("list")):       k8sauth.DecisionAllow,
		getAttributesMapkey(createNetworkPolicyTierAttr("list")):   k8sauth.DecisionDeny,
		getAttributesMapkey(createNetworkPolicyAttr("get")):        k8sauth.DecisionAllow,
		getAttributesMapkey(createNetworkPolicyTierAttr("get")):    k8sauth.DecisionDeny,
	}}
	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createNetworkPolicyContext("create"), "test-tier.test-np", "test-tier",
	); err != nil {
		t.Fatalf("Error returned creating NetworkPolicy when tier GET and named match permit the request: %v", err)
	}

	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createNetworkPolicyContext("get"), "test-tier.test-np", "test-tier",
	); err != nil {
		t.Fatalf("Error returned getting NetworkPolicy when tier GET and named match permit the request: %v", err)
	}

	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createNetworkPolicyContext("list"), "", "test-tier",
	); err != nil {
		t.Fatalf("Error returned listing NetworkPolicy when tier GET and named match permit the request: %v", err)
	}
}

func TestGlobalNetworkPolicyByName(t *testing.T) {
	ta := &testAuth{t, map[string]k8sauth.Decision{
		getAttributesMapkey(getTierAttr):                                 k8sauth.DecisionAllow,
		getAttributesMapkey(createGlobalNetworkPolicyAttr("create")):     k8sauth.DecisionAllow,
		getAttributesMapkey(createGlobalNetworkPolicyTierAttr("create")): k8sauth.DecisionDeny,
		getAttributesMapkey(createGlobalNetworkPolicyAttr("list")):       k8sauth.DecisionAllow,
		getAttributesMapkey(createGlobalNetworkPolicyTierAttr("list")):   k8sauth.DecisionDeny,
		getAttributesMapkey(createGlobalNetworkPolicyAttr("get")):        k8sauth.DecisionAllow,
		getAttributesMapkey(createGlobalNetworkPolicyTierAttr("get")):    k8sauth.DecisionDeny,
	}}
	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createGlobalNetworkPolicyContext("create"), "test-tier.test-gnp", "test-tier",
	); err != nil {
		t.Fatalf("Error returned creating GlobalNetworkPolicy when tier GET and named match permit the request: %v", err)
	}

	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createGlobalNetworkPolicyContext("get"), "test-tier.test-gnp", "test-tier",
	); err != nil {
		t.Fatalf("Error returned getting GlobalNetworkPolicy when tier GET and named match permit the request: %v", err)
	}

	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createGlobalNetworkPolicyContext("list"), "", "test-tier",
	); err != nil {
		t.Fatalf("Error returned listing GlobalNetworkPolicy when tier GET and named match permit the request: %v", err)
	}
}

func TestNetworkPolicyDenied(t *testing.T) {
	ta := &testAuth{t, map[string]k8sauth.Decision{
		getAttributesMapkey(getTierAttr):                           k8sauth.DecisionAllow,
		getAttributesMapkey(createNetworkPolicyAttr("create")):     k8sauth.DecisionDeny,
		getAttributesMapkey(createNetworkPolicyTierAttr("create")): k8sauth.DecisionDeny,
		getAttributesMapkey(createNetworkPolicyAttr("list")):       k8sauth.DecisionDeny,
		getAttributesMapkey(createNetworkPolicyTierAttr("list")):   k8sauth.DecisionDeny,
		getAttributesMapkey(createNetworkPolicyAttr("delete")):     k8sauth.DecisionDeny,
		getAttributesMapkey(createNetworkPolicyTierAttr("delete")): k8sauth.DecisionDeny,
	}}
	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createNetworkPolicyContext("create"), "test-tier.test-np", "test-tier",
	); err == nil {
		t.Fatalf("No error returned creating NetworkPolicy when not permitted by NetworkPolicy RBAC")
	} else if err.Error() != createNetworkPolicyError("create", false) {
		t.Fatalf("Incorrect error message creating NetworkPolicy when not permitted by NetworkPolicy RBAC: %v", err)
	}

	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createNetworkPolicyContext("delete"), "test-tier.test-np", "test-tier",
	); err == nil {
		t.Fatalf("No error returned deleting NetworkPolicy when not permitted by NetworkPolicy RBAC")
	} else if err.Error() != createNetworkPolicyError("delete", false) {
		t.Fatalf("Incorrect error message deleting NetworkPolicy when not permitted by NetworkPolicy RBAC: %v", err)
	}

	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createNetworkPolicyContext("list"), "", "test-tier",
	); err == nil {
		t.Fatalf("No error returned listing NetworkPolicy when not permitted by NetworkPolicy RBAC")
	} else if err.Error() != createNetworkPolicyError("list", false) {
		t.Fatalf("Incorrect error message listing NetworkPolicy when not permitted by NetworkPolicy RBAC: %v", err)
	}
}

func TestGlobalNetworkPolicyDenied(t *testing.T) {
	ta := &testAuth{t, map[string]k8sauth.Decision{
		getAttributesMapkey(getTierAttr):                                 k8sauth.DecisionAllow,
		getAttributesMapkey(createGlobalNetworkPolicyAttr("create")):     k8sauth.DecisionDeny,
		getAttributesMapkey(createGlobalNetworkPolicyTierAttr("create")): k8sauth.DecisionDeny,
		getAttributesMapkey(createGlobalNetworkPolicyAttr("list")):       k8sauth.DecisionDeny,
		getAttributesMapkey(createGlobalNetworkPolicyTierAttr("list")):   k8sauth.DecisionDeny,
		getAttributesMapkey(createGlobalNetworkPolicyAttr("get")):        k8sauth.DecisionDeny,
		getAttributesMapkey(createGlobalNetworkPolicyTierAttr("get")):    k8sauth.DecisionDeny,
	}}
	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createGlobalNetworkPolicyContext("create"), "test-tier.test-gnp", "test-tier",
	); err == nil {
		t.Fatalf("No error returned creating GlobalNetworkPolicy when not permitted by GlobalNetworkPolicyRBAC")
	} else if err.Error() != createGlobalNetworkPolicyError("create", false) {
		t.Fatalf("Incorrect error message creating GlobalNetworkPolicy when not permitted by NetworkPolicy RBAC: %v", err)
	}

	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createGlobalNetworkPolicyContext("get"), "test-tier.test-gnp", "test-tier",
	); err == nil {
		t.Fatalf("No error returned deleting GlobalNetworkPolicy when not permitted by GlobalNetworkPolicyRBAC")
	} else if err.Error() != createGlobalNetworkPolicyError("get", false) {
		t.Fatalf("Incorrect error message getting GlobalNetworkPolicy when not permitted by NetworkPolicy RBAC: %v", err)
	}

	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createGlobalNetworkPolicyContext("list"), "", "test-tier",
	); err == nil {
		t.Fatalf("No error returned listing GlobalNetworkPolicy when not permitted by GlobalNetworkPolicyRBAC")
	} else if err.Error() != createGlobalNetworkPolicyError("list", false) {
		t.Fatalf("Incorrect error message listing GlobalNetworkPolicy when not permitted by NetworkPolicy RBAC: %v", err)
	}
}

// ============================================================================
// New-style (bare) policy name tests
//
// These test the same authorization paths as the old-style tests above, but
// with bare policy names (e.g., "test-np") instead of tier-prefixed names
// (e.g., "test-tier.test-np"). The authorizer should use the raw policy name
// from the request for RBAC resource name matching.
// ============================================================================

// makeNetworkPolicyAttr returns the expected RBAC attributes for a NetworkPolicy with the given name.
func makeNetworkPolicyAttr(verb, name string) k8sauth.Attributes {
	ar := k8sauth.AttributesRecord{
		User:            testUser,
		Verb:            verb,
		Namespace:       "test-namespace",
		APIGroup:        "projectcalico.org",
		APIVersion:      "v3",
		Resource:        "tier.networkpolicies",
		Name:            name,
		ResourceRequest: true,
		Path:            "/apis/projectcalico.org/v3/namespaces/test-namespace/tier.networkpolicies/" + name,
	}
	if verb == "list" || verb == "create" {
		ar.Path = "/apis/projectcalico.org/v3/namespaces/test-namespace/tier.networkpolicies"
		ar.Name = ""
	}
	return ar
}

// makeNetworkPolicyContext returns a request context for a NetworkPolicy with the given name.
// The context uses the base "networkpolicies" resource (how the real request arrives),
// while the authorizer internally re-checks against "tier.networkpolicies" for RBAC.
func makeNetworkPolicyContext(verb, name string) context.Context {
	ctx := genericapirequest.NewContext()
	ctx = genericapirequest.WithUser(ctx, testUser)
	ctx = genericapirequest.WithNamespace(ctx, "test-namespace")
	ri := &genericapirequest.RequestInfo{
		IsResourceRequest: true,
		Path:              "/apis/projectcalico.org/v3/namespaces/test-namespace/networkpolicies/" + name,
		Verb:              verb,
		APIGroup:          "projectcalico.org",
		APIVersion:        "v3",
		Resource:          "networkpolicies",
		Namespace:         "test-namespace",
		Name:              name,
	}
	if verb == "list" || verb == "create" {
		ri.Name = ""
		ri.Path = "/apis/projectcalico.org/v3/namespaces/test-namespace/networkpolicies"
	}
	ctx = genericapirequest.WithRequestInfo(ctx, ri)
	return ctx
}

func makeNetworkPolicyError(verb, policyName string, cannotGetTier bool) string {
	msg := "networkpolicies.projectcalico.org "
	if verb != "list" {
		msg += fmt.Sprintf("%q ", policyName)
	}
	msg += "is forbidden: User \"testuser\" cannot " + verb +
		" networkpolicies.projectcalico.org in tier \"test-tier\" and namespace \"test-namespace\""
	if cannotGetTier {
		msg += " (user cannot get tier)"
	}
	return msg
}

// TestNewStyleNetworkPolicyByName verifies that a bare (new-style) policy name
// works with exact resource name matching. The RBAC resourceName is "test-np"
// (the bare policy name), not "test-tier.test-np".
func TestNewStyleNetworkPolicyByName(t *testing.T) {
	ta := &testAuth{t, map[string]k8sauth.Decision{
		getAttributesMapkey(getTierAttr):                              k8sauth.DecisionAllow,
		getAttributesMapkey(makeNetworkPolicyAttr("get", "test-np")):  k8sauth.DecisionAllow,
		getAttributesMapkey(createNetworkPolicyTierAttr("get")):       k8sauth.DecisionDeny,
		getAttributesMapkey(makeNetworkPolicyAttr("list", "test-np")): k8sauth.DecisionAllow,
		getAttributesMapkey(createNetworkPolicyTierAttr("list")):      k8sauth.DecisionDeny,
	}}
	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		makeNetworkPolicyContext("get", "test-np"), "test-np", "test-tier",
	); err != nil {
		t.Fatalf("Error returned getting NetworkPolicy with bare name when named match permits: %v", err)
	}

	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		makeNetworkPolicyContext("list", "test-np"), "", "test-tier",
	); err != nil {
		t.Fatalf("Error returned listing NetworkPolicy with bare name when named match permits: %v", err)
	}
}

// TestNewStyleNetworkPolicyTierWildcard verifies that the tier.* wildcard works
// for bare (new-style) policy names, same as for old-style names.
func TestNewStyleNetworkPolicyTierWildcard(t *testing.T) {
	ta := &testAuth{t, map[string]k8sauth.Decision{
		getAttributesMapkey(getTierAttr):                                k8sauth.DecisionAllow,
		getAttributesMapkey(makeNetworkPolicyAttr("create", "test-np")): k8sauth.DecisionDeny,
		getAttributesMapkey(createNetworkPolicyTierAttr("create")):      k8sauth.DecisionAllow,
		getAttributesMapkey(makeNetworkPolicyAttr("delete", "test-np")): k8sauth.DecisionDeny,
		getAttributesMapkey(createNetworkPolicyTierAttr("delete")):      k8sauth.DecisionAllow,
	}}
	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		makeNetworkPolicyContext("create", "test-np"), "test-np", "test-tier",
	); err != nil {
		t.Fatalf("Error returned creating NetworkPolicy with bare name when wildcard permits: %v", err)
	}

	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		makeNetworkPolicyContext("delete", "test-np"), "test-np", "test-tier",
	); err != nil {
		t.Fatalf("Error returned deleting NetworkPolicy with bare name when wildcard permits: %v", err)
	}
}

// TestNewStyleNetworkPolicyDenied verifies that a bare (new-style) policy name
// is correctly denied when neither the exact name nor the tier wildcard match.
func TestNewStyleNetworkPolicyDenied(t *testing.T) {
	ta := &testAuth{t, map[string]k8sauth.Decision{
		getAttributesMapkey(getTierAttr):                                k8sauth.DecisionAllow,
		getAttributesMapkey(makeNetworkPolicyAttr("get", "test-np")):    k8sauth.DecisionDeny,
		getAttributesMapkey(createNetworkPolicyTierAttr("get")):         k8sauth.DecisionDeny,
		getAttributesMapkey(makeNetworkPolicyAttr("delete", "test-np")): k8sauth.DecisionDeny,
		getAttributesMapkey(createNetworkPolicyTierAttr("delete")):      k8sauth.DecisionDeny,
	}}
	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		makeNetworkPolicyContext("get", "test-np"), "test-np", "test-tier",
	); err == nil {
		t.Fatalf("No error returned getting NetworkPolicy with bare name when not permitted")
	} else if err.Error() != makeNetworkPolicyError("get", "test-np", false) {
		t.Fatalf("Incorrect error message: %v", err)
	}

	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		makeNetworkPolicyContext("delete", "test-np"), "test-np", "test-tier",
	); err == nil {
		t.Fatalf("No error returned deleting NetworkPolicy with bare name when not permitted")
	} else if err.Error() != makeNetworkPolicyError("delete", "test-np", false) {
		t.Fatalf("Incorrect error message: %v", err)
	}
}

// TestNewStyleNetworkPolicyNoTierGet verifies that bare (new-style) policy names
// are still denied when the user lacks tier GET access, even if the policy match
// and wildcard match would both allow.
func TestNewStyleNetworkPolicyNoTierGet(t *testing.T) {
	ta := &testAuth{t, map[string]k8sauth.Decision{
		getAttributesMapkey(getTierAttr):                                k8sauth.DecisionDeny,
		getAttributesMapkey(makeNetworkPolicyAttr("get", "test-np")):    k8sauth.DecisionAllow,
		getAttributesMapkey(createNetworkPolicyTierAttr("get")):         k8sauth.DecisionAllow,
		getAttributesMapkey(makeNetworkPolicyAttr("delete", "test-np")): k8sauth.DecisionAllow,
		getAttributesMapkey(createNetworkPolicyTierAttr("delete")):      k8sauth.DecisionAllow,
	}}
	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		makeNetworkPolicyContext("get", "test-np"), "test-np", "test-tier",
	); err == nil {
		t.Fatalf("No error returned getting NetworkPolicy with bare name when tier GET denied")
	} else if err.Error() != makeNetworkPolicyError("get", "test-np", true) {
		t.Fatalf("Incorrect error message: %v", err)
	}
}

// TestNameDisambiguation verifies that old-style (tier-prefixed) and new-style
// (bare) policy names resolve to different RBAC resource names and can be
// independently authorized. A user with access to "test-np" should not
// automatically have access to "test-tier.test-np", and vice versa.
func TestNameDisambiguation(t *testing.T) {
	// Bare name "test-np" is allowed, old-style "test-tier.test-np" is denied.
	ta := &testAuth{t, map[string]k8sauth.Decision{
		getAttributesMapkey(getTierAttr):                                       k8sauth.DecisionAllow,
		getAttributesMapkey(makeNetworkPolicyAttr("get", "test-np")):           k8sauth.DecisionAllow,
		getAttributesMapkey(createNetworkPolicyTierAttr("get")):                k8sauth.DecisionDeny,
		getAttributesMapkey(makeNetworkPolicyAttr("get", "test-tier.test-np")): k8sauth.DecisionDeny,
	}}

	// Bare name should succeed.
	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		makeNetworkPolicyContext("get", "test-np"), "test-np", "test-tier",
	); err != nil {
		t.Fatalf("Error returned getting bare-named NetworkPolicy when permitted: %v", err)
	}

	// Old-style name should be denied (different RBAC resource name).
	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		makeNetworkPolicyContext("get", "test-tier.test-np"), "test-tier.test-np", "test-tier",
	); err == nil {
		t.Fatalf("No error returned getting old-style NetworkPolicy when only bare name is permitted")
	}
}
