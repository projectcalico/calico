// Copyright (c) 2025 Tigera, Inc. All rights reserved.

// Code generated by lister-gen. DO NOT EDIT.

package v3

import (
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/listers"
	"k8s.io/client-go/tools/cache"
)

// StagedNetworkPolicyLister helps list StagedNetworkPolicies.
// All objects returned here must be treated as read-only.
type StagedNetworkPolicyLister interface {
	// List lists all StagedNetworkPolicies in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v3.StagedNetworkPolicy, err error)
	// StagedNetworkPolicies returns an object that can list and get StagedNetworkPolicies.
	StagedNetworkPolicies(namespace string) StagedNetworkPolicyNamespaceLister
	StagedNetworkPolicyListerExpansion
}

// stagedNetworkPolicyLister implements the StagedNetworkPolicyLister interface.
type stagedNetworkPolicyLister struct {
	listers.ResourceIndexer[*v3.StagedNetworkPolicy]
}

// NewStagedNetworkPolicyLister returns a new StagedNetworkPolicyLister.
func NewStagedNetworkPolicyLister(indexer cache.Indexer) StagedNetworkPolicyLister {
	return &stagedNetworkPolicyLister{listers.New[*v3.StagedNetworkPolicy](indexer, v3.Resource("stagednetworkpolicy"))}
}

// StagedNetworkPolicies returns an object that can list and get StagedNetworkPolicies.
func (s *stagedNetworkPolicyLister) StagedNetworkPolicies(namespace string) StagedNetworkPolicyNamespaceLister {
	return stagedNetworkPolicyNamespaceLister{listers.NewNamespaced[*v3.StagedNetworkPolicy](s.ResourceIndexer, namespace)}
}

// StagedNetworkPolicyNamespaceLister helps list and get StagedNetworkPolicies.
// All objects returned here must be treated as read-only.
type StagedNetworkPolicyNamespaceLister interface {
	// List lists all StagedNetworkPolicies in the indexer for a given namespace.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v3.StagedNetworkPolicy, err error)
	// Get retrieves the StagedNetworkPolicy from the indexer for a given namespace and name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v3.StagedNetworkPolicy, error)
	StagedNetworkPolicyNamespaceListerExpansion
}

// stagedNetworkPolicyNamespaceLister implements the StagedNetworkPolicyNamespaceLister
// interface.
type stagedNetworkPolicyNamespaceLister struct {
	listers.ResourceIndexer[*v3.StagedNetworkPolicy]
}
