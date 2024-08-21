// Copyright (c) 2024 Tigera, Inc. All rights reserved.

package util

import (
	"context"
	"fmt"
	"strings"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apiserver/pkg/endpoints/filters"

	"github.com/projectcalico/calico/apiserver/pkg/rbac"
	"github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/authorizer"

	metainternalversion "k8s.io/apimachinery/pkg/apis/meta/internalversion"
	"k8s.io/apimachinery/pkg/selection"
)

const (
	policyDelim = "."
)

// EnsureTierSelector parses the given options and ensures the correct tier selector is set.
// It first checks the input selector, if given. Otherwise, it uses a tier selector based on the user's permissions.
func EnsureTierSelector(ctx context.Context, options *metainternalversion.ListOptions, authorizer authorizer.TierAuthorizer, calicoResourceLister rbac.CalicoResourceLister) error {
	// Get tiers from the selector passed by the user, if any.
	tiers, err := getTiersFromSelector(options)
	if err != nil {
		return err
	}
	if tiers == nil {
		// No tiers were given - default to the tiers the user has permissions to see.
		tiers, err = getAuthorizedTiers(ctx, authorizer, calicoResourceLister)
		if err != nil {
			return err
		}

		// Update the selector on the input options to include the new tiers.
		tierSelector, err := buildSelectorFromTiers(tiers)
		if err != nil {
			return err
		}

		if options.LabelSelector == nil {
			options.LabelSelector = labels.NewSelector()
		}
		options.LabelSelector = options.LabelSelector.Add(*tierSelector)
	} else {
		err = authorizeTiers(ctx, tiers, authorizer)
		if err != nil {
			return err
		}
	}

	return nil
}

// getTiersFromSelector extracts the tiers set in the ListOptions selectors, and ensures valid list operator
func getTiersFromSelector(options *metainternalversion.ListOptions) ([]string, error) {
	if options.FieldSelector != nil {
		requirements := options.FieldSelector.Requirements()
		for _, requirement := range requirements {
			if requirement.Field == "spec.tier" {
				if requirement.Operator == selection.Equals ||
					requirement.Operator == selection.DoubleEquals {
					return []string{requirement.Value}, nil
				}
				return nil, fmt.Errorf("Non equal selector operator not supported for field spec.tier")
			}
		}
	}

	if options.LabelSelector != nil {
		requirements, _ := options.LabelSelector.Requirements()
		for _, requirement := range requirements {
			if requirement.Key() == "projectcalico.org/tier" {
				if requirement.Operator() == selection.In {
					return requirement.Values().List(), nil
				}
				if len(requirement.Values()) > 1 {
					return nil, fmt.Errorf("Non IN multi-valued selector not supported for label projectcalico.org/tier")
				}
				tierName, ok := requirement.Values().PopAny()
				if ok && (requirement.Operator() == selection.Equals ||
					requirement.Operator() == selection.DoubleEquals) {
					return []string{tierName}, nil
				}
				return nil, fmt.Errorf("Non equal selector operator not supported for label projectcalico.org/tier")
			}
		}
	}

	// Reaching here implies tier hasn't been explicitly set as part of the selectors. We set the tier to all tiers available to user
	return nil, nil
}

// getAuthorizedTiers gets all the available Tiers to the user
func getAuthorizedTiers(ctx context.Context, authorizer authorizer.TierAuthorizer, calicoResourceLister rbac.CalicoResourceLister) ([]string, error) {
	tiers, err := calicoResourceLister.ListTiers()
	if err != nil {
		return nil, err
	}
	var allowedTiers []string

	for _, tier := range tiers {
		err := authorizer.AuthorizeTierOperation(ctx, "", tier.Name)
		if err == nil {
			allowedTiers = append(allowedTiers, tier.Name)
		}
	}

	if len(allowedTiers) == 0 && len(tiers) != 0 {
		attributes, err := filters.GetAuthorizerAttributes(ctx)
		if err != nil {
			return nil, err
		}
		return nil, errors.NewForbidden(v3.Resource(attributes.GetResource()), "", fmt.Errorf("Operation on Calico tiered policy is forbidden"))
	}

	return allowedTiers, nil
}

// authorizeTiers ensures that the user has access to all the supplied Tiers
func authorizeTiers(ctx context.Context, tiers []string, authorizer authorizer.TierAuthorizer) error {
	for _, tier := range tiers {
		err := authorizer.AuthorizeTierOperation(ctx, "", tier)
		if err != nil {
			return err
		}
	}

	return nil
}

func buildSelectorFromTiers(tiers []string) (*labels.Requirement, error) {
	requirement, err := labels.NewRequirement("projectcalico.org/tier", selection.In, tiers)
	if err != nil {
		return nil, err
	}

	return requirement, nil
}

// GetTierFromPolicyName extracts the Tier name from the policy name.
func GetTierFromPolicyName(policyName string) (string, string) {
	policySlice := strings.Split(policyName, policyDelim)
	if len(policySlice) < 2 {
		return "default", policySlice[0]
	}
	return policySlice[0], policySlice[1]
}
