// Copyright (c) 2025 Tigera, Inc. All rights reserved.

// Code generated by lister-gen. DO NOT EDIT.

package v3

import (
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/listers"
	"k8s.io/client-go/tools/cache"
)

// CalicoNodeStatusLister helps list CalicoNodeStatuses.
// All objects returned here must be treated as read-only.
type CalicoNodeStatusLister interface {
	// List lists all CalicoNodeStatuses in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v3.CalicoNodeStatus, err error)
	// Get retrieves the CalicoNodeStatus from the index for a given name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v3.CalicoNodeStatus, error)
	CalicoNodeStatusListerExpansion
}

// calicoNodeStatusLister implements the CalicoNodeStatusLister interface.
type calicoNodeStatusLister struct {
	listers.ResourceIndexer[*v3.CalicoNodeStatus]
}

// NewCalicoNodeStatusLister returns a new CalicoNodeStatusLister.
func NewCalicoNodeStatusLister(indexer cache.Indexer) CalicoNodeStatusLister {
	return &calicoNodeStatusLister{listers.New[*v3.CalicoNodeStatus](indexer, v3.Resource("caliconodestatus"))}
}
