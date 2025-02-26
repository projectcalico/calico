// Copyright (c) 2025 Tigera, Inc. All rights reserved.

// Code generated by lister-gen. DO NOT EDIT.

package v3

import (
	projectcalicov3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	labels "k8s.io/apimachinery/pkg/labels"
	listers "k8s.io/client-go/listers"
	cache "k8s.io/client-go/tools/cache"
)

// FelixConfigurationLister helps list FelixConfigurations.
// All objects returned here must be treated as read-only.
type FelixConfigurationLister interface {
	// List lists all FelixConfigurations in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*projectcalicov3.FelixConfiguration, err error)
	// Get retrieves the FelixConfiguration from the index for a given name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*projectcalicov3.FelixConfiguration, error)
	FelixConfigurationListerExpansion
}

// felixConfigurationLister implements the FelixConfigurationLister interface.
type felixConfigurationLister struct {
	listers.ResourceIndexer[*projectcalicov3.FelixConfiguration]
}

// NewFelixConfigurationLister returns a new FelixConfigurationLister.
func NewFelixConfigurationLister(indexer cache.Indexer) FelixConfigurationLister {
	return &felixConfigurationLister{listers.New[*projectcalicov3.FelixConfiguration](indexer, projectcalicov3.Resource("felixconfiguration"))}
}
