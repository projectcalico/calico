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

// FakeNetworkSets implements NetworkSetInterface
type FakeNetworkSets struct {
	Fake *FakeProjectcalicoV3
	ns   string
}

var networksetsResource = v3.SchemeGroupVersion.WithResource("networksets")

var networksetsKind = v3.SchemeGroupVersion.WithKind("NetworkSet")

// Get takes name of the networkSet, and returns the corresponding networkSet object, and an error if there is any.
func (c *FakeNetworkSets) Get(ctx context.Context, name string, options v1.GetOptions) (result *v3.NetworkSet, err error) {
	emptyResult := &v3.NetworkSet{}
	obj, err := c.Fake.
		Invokes(testing.NewGetActionWithOptions(networksetsResource, c.ns, name, options), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v3.NetworkSet), err
}

// List takes label and field selectors, and returns the list of NetworkSets that match those selectors.
func (c *FakeNetworkSets) List(ctx context.Context, opts v1.ListOptions) (result *v3.NetworkSetList, err error) {
	emptyResult := &v3.NetworkSetList{}
	obj, err := c.Fake.
		Invokes(testing.NewListActionWithOptions(networksetsResource, networksetsKind, c.ns, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v3.NetworkSetList{ListMeta: obj.(*v3.NetworkSetList).ListMeta}
	for _, item := range obj.(*v3.NetworkSetList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested networkSets.
func (c *FakeNetworkSets) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchActionWithOptions(networksetsResource, c.ns, opts))

}

// Create takes the representation of a networkSet and creates it.  Returns the server's representation of the networkSet, and an error, if there is any.
func (c *FakeNetworkSets) Create(ctx context.Context, networkSet *v3.NetworkSet, opts v1.CreateOptions) (result *v3.NetworkSet, err error) {
	emptyResult := &v3.NetworkSet{}
	obj, err := c.Fake.
		Invokes(testing.NewCreateActionWithOptions(networksetsResource, c.ns, networkSet, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v3.NetworkSet), err
}

// Update takes the representation of a networkSet and updates it. Returns the server's representation of the networkSet, and an error, if there is any.
func (c *FakeNetworkSets) Update(ctx context.Context, networkSet *v3.NetworkSet, opts v1.UpdateOptions) (result *v3.NetworkSet, err error) {
	emptyResult := &v3.NetworkSet{}
	obj, err := c.Fake.
		Invokes(testing.NewUpdateActionWithOptions(networksetsResource, c.ns, networkSet, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v3.NetworkSet), err
}

// Delete takes name of the networkSet and deletes it. Returns an error if one occurs.
func (c *FakeNetworkSets) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteActionWithOptions(networksetsResource, c.ns, name, opts), &v3.NetworkSet{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeNetworkSets) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewDeleteCollectionActionWithOptions(networksetsResource, c.ns, opts, listOpts)

	_, err := c.Fake.Invokes(action, &v3.NetworkSetList{})
	return err
}

// Patch applies the patch and returns the patched networkSet.
func (c *FakeNetworkSets) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v3.NetworkSet, err error) {
	emptyResult := &v3.NetworkSet{}
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceActionWithOptions(networksetsResource, c.ns, name, pt, data, opts, subresources...), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v3.NetworkSet), err
}
