// Copyright (c) 2024 Tigera, Inc. All rights reserved.

package authorizer

import (
	"context"
	"fmt"
	"sync"

	"k8s.io/klog/v2"

	calico "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"k8s.io/apimachinery/pkg/api/errors"
	k8sauth "k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/filters"
)

type TierAuthorizer interface {
	// AuthorizeTierOperation checks whether the request is for a tiered policy, and if so checks
	// whether the user us authorized to perform the operation. Returns a Forbidden error  if the
	// operation is not authorized.
	AuthorizeTierOperation(ctx context.Context, policyName string, tierName string) error
}

type authorizer struct {
	k8sauth.Authorizer
}

// Returns a new TierAuthorizer that uses the provided standard authorizer to perform the underlying
// lookups.
func NewTierAuthorizer(a k8sauth.Authorizer) TierAuthorizer {
	return &authorizer{a}
}

// AuthorizeTierOperation implements the TierAuthorizer interface.
func (a *authorizer) AuthorizeTierOperation(
	ctx context.Context,
	policyName string,
	tierName string,
) error {
	if a.Authorizer == nil {
		klog.V(4).Info("No authorizer - allow operation")
		return nil
	}

	attributes, err := filters.GetAuthorizerAttributes(ctx)
	if err != nil {
		klog.Errorf("Unable to extract authorizer attributes: %s", err)
		return err
	}

	// Log the original authorizer attributes.
	logAuthorizerAttributes(attributes)

	// We need to check whether the user is authorized to perform the action on the tier.<resourcetype>
	// resource, with a resource name of either:
	// - <tier>.*         (this is the wildcard syntax for any Calico policy within a tier)
	// - <tier>.<policy>  (this checks for a specific policy and tier, or fully wildcarded policy and tier)
	// *and* has GET access for the tier.
	// These requests can be performed in parallel.
	wg := sync.WaitGroup{}
	wg.Add(3)

	// Query GET access for the tier.
	var decisionGetTier k8sauth.Decision
	go func() {
		defer wg.Done()
		attrs := k8sauth.AttributesRecord{
			User:            attributes.GetUser(),
			Verb:            "get",
			Namespace:       "",
			APIGroup:        attributes.GetAPIGroup(),
			APIVersion:      attributes.GetAPIVersion(),
			Resource:        "tiers",
			Subresource:     "",
			Name:            tierName,
			ResourceRequest: true,
			Path:            "/apis/projectcalico.org/v3/tiers/" + tierName,
		}

		klog.V(4).Infof("Checking authorization using tier resource type (user can get tier)")
		logAuthorizerAttributes(attrs)
		decisionGetTier, _, _ = a.Authorizer.Authorize(context.TODO(), attrs)
	}()

	// Query required access to the tiered policy resource or tier wildcard resource.
	var decisionPolicy, decisionTierWildcard k8sauth.Decision
	var pathPrefix string
	tierScopedResource := "tier." + attributes.GetResource()
	if attributes.GetNamespace() == "" {
		pathPrefix = "/apis/projectcalico.org/v3/" + tierScopedResource
	} else {
		pathPrefix = "/apis/projectcalico.org/v3/namespaces/" + attributes.GetNamespace() + "/" + tierScopedResource
	}
	go func() {
		defer wg.Done()
		path := pathPrefix
		if attributes.GetName() != "" {
			path = pathPrefix + "/" + attributes.GetName()
		}
		attrs := k8sauth.AttributesRecord{
			User:            attributes.GetUser(),
			Verb:            attributes.GetVerb(),
			Namespace:       attributes.GetNamespace(),
			APIGroup:        attributes.GetAPIGroup(),
			APIVersion:      attributes.GetAPIVersion(),
			Resource:        tierScopedResource,
			Subresource:     attributes.GetSubresource(),
			Name:            attributes.GetName(),
			ResourceRequest: true,
			Path:            path,
		}

		klog.V(4).Infof("Checking authorization using tier scoped resource type (policy name match)")
		logAuthorizerAttributes(attrs)
		decisionPolicy, _, _ = a.Authorizer.Authorize(context.TODO(), attrs)
	}()
	go func() {
		defer wg.Done()
		name := tierName + ".*"
		path := pathPrefix + "/" + name
		attrs := k8sauth.AttributesRecord{
			User:            attributes.GetUser(),
			Verb:            attributes.GetVerb(),
			Namespace:       attributes.GetNamespace(),
			APIGroup:        attributes.GetAPIGroup(),
			APIVersion:      attributes.GetAPIVersion(),
			Resource:        tierScopedResource,
			Subresource:     attributes.GetSubresource(),
			Name:            name,
			ResourceRequest: true,
			Path:            path,
		}

		klog.V(4).Infof("Checking authorization using tier scoped resource type (tier name match)")
		logAuthorizerAttributes(attrs)
		decisionTierWildcard, _, _ = a.Authorizer.Authorize(context.TODO(), attrs)
	}()

	// Wait for the requests to complete.
	wg.Wait()

	// If the user has GET access to the tier and either the policy match or tier wildcard match are authorized
	// then allow the request.
	if decisionGetTier == k8sauth.DecisionAllow &&
		(decisionPolicy == k8sauth.DecisionAllow || decisionTierWildcard == k8sauth.DecisionAllow) {
		klog.Infof("Operation allowed")
		return nil
	}

	// Request is forbidden.
	reason := forbiddenMessage(attributes, "tier", tierName, decisionGetTier)
	klog.V(4).Infof("Operation on Calico tiered policy is forbidden: %v", reason)
	return errors.NewForbidden(calico.Resource(attributes.GetResource()), policyName, fmt.Errorf("%s", reason))
}

// forbiddenMessage crafts the appropriate forbidden message for our special hierarchically owned resource types. This
// is largely copied from k8s.io/apiserver/pkg/endpoints/handlers/responsewriters/errors.go
func forbiddenMessage(attributes k8sauth.Attributes, ownerResource, ownerName string, decisionGetOwner k8sauth.Decision) string {
	username := ""
	if user := attributes.GetUser(); user != nil {
		username = user.GetName()
	}

	resource := attributes.GetResource()
	if group := attributes.GetAPIGroup(); len(group) > 0 {
		resource = resource + "." + group
	}
	if subresource := attributes.GetSubresource(); len(subresource) > 0 {
		resource = resource + "/" + subresource
	}

	var msg string
	if ns := attributes.GetNamespace(); len(ns) > 0 {
		msg = fmt.Sprintf("User %q cannot %s %s in %s %q and namespace %q", username, attributes.GetVerb(), resource, ownerResource, ownerName, ns)
	} else {
		msg = fmt.Sprintf("User %q cannot %s %s in %s %q", username, attributes.GetVerb(), resource, ownerResource, ownerName)
	}

	// If the user does not have get access to the tier, append additional text to the message.
	if decisionGetOwner != k8sauth.DecisionAllow {
		msg += fmt.Sprintf(" (user cannot get %s)", ownerResource)
	}
	return msg
}

// logAuthorizerAttributes logs out the auth attributes.
func logAuthorizerAttributes(requestAttributes k8sauth.Attributes) {
	if klog.V(4).Enabled() {
		klog.Infof("Authorizer APIGroup: %s", requestAttributes.GetAPIGroup())
		klog.Infof("Authorizer APIVersion: %s", requestAttributes.GetAPIVersion())
		klog.Infof("Authorizer Name: %s", requestAttributes.GetName())
		klog.Infof("Authorizer Namespace: %s", requestAttributes.GetNamespace())
		klog.Infof("Authorizer Resource: %s", requestAttributes.GetResource())
		klog.Infof("Authorizer Subresource: %s", requestAttributes.GetSubresource())
		klog.Infof("Authorizer User: %s", requestAttributes.GetUser())
		klog.Infof("Authorizer Verb: %s", requestAttributes.GetVerb())
		klog.Infof("Authorizer Path: %s", requestAttributes.GetPath())
	}
}
