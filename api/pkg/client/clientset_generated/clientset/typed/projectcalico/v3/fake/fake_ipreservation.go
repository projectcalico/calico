// Copyright (c) 2025 Tigera, Inc. All rights reserved.

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeIPReservations implements IPReservationInterface
type FakeIPReservations struct {
	Fake *FakeProjectcalicoV3
}

var ipreservationsResource = v3.SchemeGroupVersion.WithResource("ipreservations")

var ipreservationsKind = v3.SchemeGroupVersion.WithKind("IPReservation")

// Get takes name of the iPReservation, and returns the corresponding iPReservation object, and an error if there is any.
func (c *FakeIPReservations) Get(ctx context.Context, name string, options v1.GetOptions) (result *v3.IPReservation, err error) {
	emptyResult := &v3.IPReservation{}
	obj, err := c.Fake.
		Invokes(testing.NewRootGetActionWithOptions(ipreservationsResource, name, options), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v3.IPReservation), err
}

// List takes label and field selectors, and returns the list of IPReservations that match those selectors.
func (c *FakeIPReservations) List(ctx context.Context, opts v1.ListOptions) (result *v3.IPReservationList, err error) {
	emptyResult := &v3.IPReservationList{}
	obj, err := c.Fake.
		Invokes(testing.NewRootListActionWithOptions(ipreservationsResource, ipreservationsKind, opts), emptyResult)
	if obj == nil {
		return emptyResult, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v3.IPReservationList{ListMeta: obj.(*v3.IPReservationList).ListMeta}
	for _, item := range obj.(*v3.IPReservationList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested iPReservations.
func (c *FakeIPReservations) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchActionWithOptions(ipreservationsResource, opts))
}

// Create takes the representation of a iPReservation and creates it.  Returns the server's representation of the iPReservation, and an error, if there is any.
func (c *FakeIPReservations) Create(ctx context.Context, iPReservation *v3.IPReservation, opts v1.CreateOptions) (result *v3.IPReservation, err error) {
	emptyResult := &v3.IPReservation{}
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateActionWithOptions(ipreservationsResource, iPReservation, opts), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v3.IPReservation), err
}

// Update takes the representation of a iPReservation and updates it. Returns the server's representation of the iPReservation, and an error, if there is any.
func (c *FakeIPReservations) Update(ctx context.Context, iPReservation *v3.IPReservation, opts v1.UpdateOptions) (result *v3.IPReservation, err error) {
	emptyResult := &v3.IPReservation{}
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateActionWithOptions(ipreservationsResource, iPReservation, opts), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v3.IPReservation), err
}

// Delete takes name of the iPReservation and deletes it. Returns an error if one occurs.
func (c *FakeIPReservations) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteActionWithOptions(ipreservationsResource, name, opts), &v3.IPReservation{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeIPReservations) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewRootDeleteCollectionActionWithOptions(ipreservationsResource, opts, listOpts)

	_, err := c.Fake.Invokes(action, &v3.IPReservationList{})
	return err
}

// Patch applies the patch and returns the patched iPReservation.
func (c *FakeIPReservations) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v3.IPReservation, err error) {
	emptyResult := &v3.IPReservation{}
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceActionWithOptions(ipreservationsResource, name, pt, data, opts, subresources...), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v3.IPReservation), err
}
