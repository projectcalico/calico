// Copyright (c) 2024 Tigera, Inc. All rights reserved.

package authorizer_test

import (
	"context"
	"testing"

	"k8s.io/apiserver/pkg/authentication/user"
	k8sauth "k8s.io/apiserver/pkg/authorization/authorizer"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"

	"github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/authorizer"
)

type testAuth struct {
	t      *testing.T
	lookup map[k8sauth.Attributes]k8sauth.Decision
}

func (t *testAuth) Authorize(ctx context.Context, a k8sauth.Attributes) (authorized k8sauth.Decision, reason string, err error) {
	d, ok := t.lookup[a]
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

// createGnpAttr returns the expected attributes for a GNP
func createGnpAttr(verb string) k8sauth.Attributes {
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

// createGnpTierAttr returns the expected attributes for a tier wildcard GNP match
func createGnpTierAttr(verb string) k8sauth.Attributes {
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

// createNpAttr returns the expected attributes for a NP
func createNpAttr(verb string) k8sauth.Attributes {
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

// createNpTierAttr returns the expected attributes for a tier wildcard NP match
func createNpTierAttr(verb string) k8sauth.Attributes {
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

// createGnpContext returns the expected attributes for a tier wildcard NP match
func createGnpContext(verb string) context.Context {
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

// createNpContext returns the expected attributes for a tier wildcard NP match
func createNpContext(verb string) context.Context {
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

func createNpError(verb string, cannotGetTier bool) string {
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

func createGnpError(verb string, cannotGetTier bool) string {
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
	ta := &testAuth{t, map[k8sauth.Attributes]k8sauth.Decision{
		getTierAttr:                k8sauth.DecisionDeny,
		createNpAttr("create"):     k8sauth.DecisionAllow,
		createNpTierAttr("create"): k8sauth.DecisionAllow,
		createNpAttr("list"):       k8sauth.DecisionAllow,
		createNpTierAttr("list"):   k8sauth.DecisionAllow,
		createNpAttr("delete"):     k8sauth.DecisionAllow,
		createNpTierAttr("delete"): k8sauth.DecisionAllow,
	}}
	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createNpContext("create"), "test-tier.test-np", "test-tier",
	); err == nil {
		t.Fatalf("No error returned creating NP when tier GET not permitted")
	} else if err.Error() != createNpError("create", true) {
		t.Fatalf("Incorrect error message creating NP when tier GET not permitted: %v", err)
	}

	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createNpContext("delete"), "test-tier.test-np", "test-tier",
	); err == nil {
		t.Fatalf("No error returned deleting NP when tier GET not permitted")
	} else if err.Error() != createNpError("delete", true) {
		t.Fatalf("Incorrect error message deleting NP when tier GET not permitted: %v", err)
	}

	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createNpContext("list"), "", "test-tier",
	); err == nil {
		t.Fatalf("No error returned listing NP when tier GET not permitted")
	} else if err.Error() != createNpError("list", true) {
		t.Fatalf("Incorrect error message listing NP when tier GET not permitted: %v", err)
	}
}

func TestGlobalNetworkPolicyNoTierGet(t *testing.T) {
	ta := &testAuth{t, map[k8sauth.Attributes]k8sauth.Decision{
		getTierAttr:                 k8sauth.DecisionDeny,
		createGnpAttr("create"):     k8sauth.DecisionAllow,
		createGnpTierAttr("create"): k8sauth.DecisionAllow,
		createGnpAttr("list"):       k8sauth.DecisionAllow,
		createGnpTierAttr("list"):   k8sauth.DecisionAllow,
		createGnpAttr("get"):        k8sauth.DecisionAllow,
		createGnpTierAttr("get"):    k8sauth.DecisionAllow,
	}}
	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createGnpContext("create"), "test-tier.test-gnp", "test-tier",
	); err == nil {
		t.Fatalf("No error returned creating GNP when tier GET not permitted")
	} else if err.Error() != createGnpError("create", true) {
		t.Fatalf("Incorrect error message creating GNP when tier GET not permitted: %v", err)
	}

	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createGnpContext("get"), "test-tier.test-gnp", "test-tier",
	); err == nil {
		t.Fatalf("No error returned getting GNP when tier GET not permitted")
	} else if err.Error() != createGnpError("get", true) {
		t.Fatalf("Incorrect error message getting GNP when tier GET not permitted: %v", err)
	}

	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createGnpContext("list"), "", "test-tier",
	); err == nil {
		t.Fatalf("No error returned listing GNP when tier GET not permitted")
	} else if err.Error() != createGnpError("list", true) {
		t.Fatalf("Incorrect error message listing GNP when tier GET not permitted: %v", err)
	}
}

func TestNetworkPolicyTierWildcard(t *testing.T) {
	ta := &testAuth{t, map[k8sauth.Attributes]k8sauth.Decision{
		getTierAttr:                k8sauth.DecisionAllow,
		createNpAttr("create"):     k8sauth.DecisionDeny,
		createNpTierAttr("create"): k8sauth.DecisionAllow,
		createNpAttr("list"):       k8sauth.DecisionDeny,
		createNpTierAttr("list"):   k8sauth.DecisionAllow,
		createNpAttr("delete"):     k8sauth.DecisionDeny,
		createNpTierAttr("delete"): k8sauth.DecisionAllow,
	}}
	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createNpContext("create"), "test-tier.test-np", "test-tier",
	); err != nil {
		t.Fatalf("Error returned creating NP when tier GET and wildcard match permit the request: %v", err)
	}

	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createNpContext("delete"), "test-tier.test-np", "test-tier",
	); err != nil {
		t.Fatalf("Error returned deleting NP when tier GET and wildcard match permit the request: %v", err)
	}

	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createNpContext("list"), "", "test-tier",
	); err != nil {
		t.Fatalf("Error returned listing NP when tier GET and wildcard match permit the request: %v", err)
	}
}

func TestGlobalNetworkPolicyTierWildcard(t *testing.T) {
	ta := &testAuth{t, map[k8sauth.Attributes]k8sauth.Decision{
		getTierAttr:                 k8sauth.DecisionAllow,
		createGnpAttr("create"):     k8sauth.DecisionDeny,
		createGnpTierAttr("create"): k8sauth.DecisionAllow,
		createGnpAttr("list"):       k8sauth.DecisionDeny,
		createGnpTierAttr("list"):   k8sauth.DecisionAllow,
		createGnpAttr("delete"):     k8sauth.DecisionDeny,
		createGnpTierAttr("delete"): k8sauth.DecisionAllow,
	}}
	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createGnpContext("create"), "test-tier.test-gnp", "test-tier",
	); err != nil {
		t.Fatalf("Error returned creating GNP when tier GET and wildcard match permit the request: %v", err)
	}

	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createGnpContext("delete"), "test-tier.test-gnp", "test-tier",
	); err != nil {
		t.Fatalf("Error returned deleting GNP when tier GET and wildcard match permit the request: %v", err)
	}

	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createGnpContext("list"), "", "test-tier",
	); err != nil {
		t.Fatalf("Error returned listing GNP when tier GET and wildcard match permit the request: %v", err)
	}
}

func TestNetworkPolicyByName(t *testing.T) {
	ta := &testAuth{t, map[k8sauth.Attributes]k8sauth.Decision{
		getTierAttr:                k8sauth.DecisionAllow,
		createNpAttr("create"):     k8sauth.DecisionAllow,
		createNpTierAttr("create"): k8sauth.DecisionDeny,
		createNpAttr("list"):       k8sauth.DecisionAllow,
		createNpTierAttr("list"):   k8sauth.DecisionDeny,
		createNpAttr("get"):        k8sauth.DecisionAllow,
		createNpTierAttr("get"):    k8sauth.DecisionDeny,
	}}
	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createNpContext("create"), "test-tier.test-np", "test-tier",
	); err != nil {
		t.Fatalf("Error returned creating NP when tier GET and named match permit the request: %v", err)
	}

	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createNpContext("get"), "test-tier.test-np", "test-tier",
	); err != nil {
		t.Fatalf("Error returned getting NP when tier GET and named match permit the request: %v", err)
	}

	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createNpContext("list"), "", "test-tier",
	); err != nil {
		t.Fatalf("Error returned listing NP when tier GET and named match permit the request: %v", err)
	}
}

func TestGlobalNetworkPolicyByName(t *testing.T) {
	ta := &testAuth{t, map[k8sauth.Attributes]k8sauth.Decision{
		getTierAttr:                 k8sauth.DecisionAllow,
		createGnpAttr("create"):     k8sauth.DecisionAllow,
		createGnpTierAttr("create"): k8sauth.DecisionDeny,
		createGnpAttr("list"):       k8sauth.DecisionAllow,
		createGnpTierAttr("list"):   k8sauth.DecisionDeny,
		createGnpAttr("get"):        k8sauth.DecisionAllow,
		createGnpTierAttr("get"):    k8sauth.DecisionDeny,
	}}
	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createGnpContext("create"), "test-tier.test-gnp", "test-tier",
	); err != nil {
		t.Fatalf("Error returned creating GNP when tier GET and named match permit the request: %v", err)
	}

	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createGnpContext("get"), "test-tier.test-gnp", "test-tier",
	); err != nil {
		t.Fatalf("Error returned getting GNP when tier GET and named match permit the request: %v", err)
	}

	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createGnpContext("list"), "", "test-tier",
	); err != nil {
		t.Fatalf("Error returned listing GNP when tier GET and named match permit the request: %v", err)
	}
}

func TestNetworkPolicyDenied(t *testing.T) {
	ta := &testAuth{t, map[k8sauth.Attributes]k8sauth.Decision{
		getTierAttr:                k8sauth.DecisionAllow,
		createNpAttr("create"):     k8sauth.DecisionDeny,
		createNpTierAttr("create"): k8sauth.DecisionDeny,
		createNpAttr("list"):       k8sauth.DecisionDeny,
		createNpTierAttr("list"):   k8sauth.DecisionDeny,
		createNpAttr("delete"):     k8sauth.DecisionDeny,
		createNpTierAttr("delete"): k8sauth.DecisionDeny,
	}}
	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createNpContext("create"), "test-tier.test-np", "test-tier",
	); err == nil {
		t.Fatalf("No error returned creating NP when not permitted by NP RBAC")
	} else if err.Error() != createNpError("create", false) {
		t.Fatalf("Incorrect error message creating NP when not permitted by NP RBAC: %v", err)
	}

	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createNpContext("delete"), "test-tier.test-np", "test-tier",
	); err == nil {
		t.Fatalf("No error returned deleting NP when not permitted by NP RBAC")
	} else if err.Error() != createNpError("delete", false) {
		t.Fatalf("Incorrect error message deleting NP when not permitted by NP RBAC: %v", err)
	}

	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createNpContext("list"), "", "test-tier",
	); err == nil {
		t.Fatalf("No error returned listing NP when not permitted by NP RBAC")
	} else if err.Error() != createNpError("list", false) {
		t.Fatalf("Incorrect error message listing NP when not permitted by NP RBAC: %v", err)
	}
}

func TestGlobalNetworkPolicyDenied(t *testing.T) {
	ta := &testAuth{t, map[k8sauth.Attributes]k8sauth.Decision{
		getTierAttr:                 k8sauth.DecisionAllow,
		createGnpAttr("create"):     k8sauth.DecisionDeny,
		createGnpTierAttr("create"): k8sauth.DecisionDeny,
		createGnpAttr("list"):       k8sauth.DecisionDeny,
		createGnpTierAttr("list"):   k8sauth.DecisionDeny,
		createGnpAttr("get"):        k8sauth.DecisionDeny,
		createGnpTierAttr("get"):    k8sauth.DecisionDeny,
	}}
	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createGnpContext("create"), "test-tier.test-gnp", "test-tier",
	); err == nil {
		t.Fatalf("No error returned creating GNP when not permitted by GNP RBAC")
	} else if err.Error() != createGnpError("create", false) {
		t.Fatalf("Incorrect error message creating GNP when not permitted by NP RBAC: %v", err)
	}

	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createGnpContext("get"), "test-tier.test-gnp", "test-tier",
	); err == nil {
		t.Fatalf("No error returned deleting GNP when not permitted by GNP RBAC")
	} else if err.Error() != createGnpError("get", false) {
		t.Fatalf("Incorrect error message getting GNP when not permitted by NP RBAC: %v", err)
	}

	if err := authorizer.NewTierAuthorizer(ta).AuthorizeTierOperation(
		createGnpContext("list"), "", "test-tier",
	); err == nil {
		t.Fatalf("No error returned listing GNP when not permitted by GNP RBAC")
	} else if err.Error() != createGnpError("list", false) {
		t.Fatalf("Incorrect error message listing GNP when not permitted by NP RBAC: %v", err)
	}
}
