// Copyright (c) 2025 Tigera, Inc. All rights reserved.

// Code generated by lister-gen. DO NOT EDIT.

package v3

import (
	projectcalicov3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	labels "k8s.io/apimachinery/pkg/labels"
	listers "k8s.io/client-go/listers"
	cache "k8s.io/client-go/tools/cache"
)

// IPReservationLister helps list IPReservations.
// All objects returned here must be treated as read-only.
type IPReservationLister interface {
	// List lists all IPReservations in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*projectcalicov3.IPReservation, err error)
	// Get retrieves the IPReservation from the index for a given name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*projectcalicov3.IPReservation, error)
	IPReservationListerExpansion
}

// iPReservationLister implements the IPReservationLister interface.
type iPReservationLister struct {
	listers.ResourceIndexer[*projectcalicov3.IPReservation]
}

// NewIPReservationLister returns a new IPReservationLister.
func NewIPReservationLister(indexer cache.Indexer) IPReservationLister {
	return &iPReservationLister{listers.New[*projectcalicov3.IPReservation](indexer, projectcalicov3.Resource("ipreservation"))}
}
