// Copyright (c) 2025 Tigera, Inc. All rights reserved.

// Code generated by lister-gen. DO NOT EDIT.

package v3

import (
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/listers"
	"k8s.io/client-go/tools/cache"
)

// NetworkSetLister helps list NetworkSets.
// All objects returned here must be treated as read-only.
type NetworkSetLister interface {
	// List lists all NetworkSets in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v3.NetworkSet, err error)
	// NetworkSets returns an object that can list and get NetworkSets.
	NetworkSets(namespace string) NetworkSetNamespaceLister
	NetworkSetListerExpansion
}

// networkSetLister implements the NetworkSetLister interface.
type networkSetLister struct {
	listers.ResourceIndexer[*v3.NetworkSet]
}

// NewNetworkSetLister returns a new NetworkSetLister.
func NewNetworkSetLister(indexer cache.Indexer) NetworkSetLister {
	return &networkSetLister{listers.New[*v3.NetworkSet](indexer, v3.Resource("networkset"))}
}

// NetworkSets returns an object that can list and get NetworkSets.
func (s *networkSetLister) NetworkSets(namespace string) NetworkSetNamespaceLister {
	return networkSetNamespaceLister{listers.NewNamespaced[*v3.NetworkSet](s.ResourceIndexer, namespace)}
}

// NetworkSetNamespaceLister helps list and get NetworkSets.
// All objects returned here must be treated as read-only.
type NetworkSetNamespaceLister interface {
	// List lists all NetworkSets in the indexer for a given namespace.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v3.NetworkSet, err error)
	// Get retrieves the NetworkSet from the indexer for a given namespace and name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v3.NetworkSet, error)
	NetworkSetNamespaceListerExpansion
}

// networkSetNamespaceLister implements the NetworkSetNamespaceLister
// interface.
type networkSetNamespaceLister struct {
	listers.ResourceIndexer[*v3.NetworkSet]
}
