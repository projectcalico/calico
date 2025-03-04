// Copyright (c) 2025 Tigera, Inc. All rights reserved.

// Code generated by lister-gen. DO NOT EDIT.

package v3

import (
	projectcalicov3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	labels "k8s.io/apimachinery/pkg/labels"
	listers "k8s.io/client-go/listers"
	cache "k8s.io/client-go/tools/cache"
)

// BlockAffinityLister helps list BlockAffinities.
// All objects returned here must be treated as read-only.
type BlockAffinityLister interface {
	// List lists all BlockAffinities in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*projectcalicov3.BlockAffinity, err error)
	// Get retrieves the BlockAffinity from the index for a given name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*projectcalicov3.BlockAffinity, error)
	BlockAffinityListerExpansion
}

// blockAffinityLister implements the BlockAffinityLister interface.
type blockAffinityLister struct {
	listers.ResourceIndexer[*projectcalicov3.BlockAffinity]
}

// NewBlockAffinityLister returns a new BlockAffinityLister.
func NewBlockAffinityLister(indexer cache.Indexer) BlockAffinityLister {
	return &blockAffinityLister{listers.New[*projectcalicov3.BlockAffinity](indexer, projectcalicov3.Resource("blockaffinity"))}
}
