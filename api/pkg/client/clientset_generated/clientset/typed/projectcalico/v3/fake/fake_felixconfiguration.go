// Copyright (c) 2024 Tigera, Inc. All rights reserved.

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeFelixConfigurations implements FelixConfigurationInterface
type FakeFelixConfigurations struct {
	Fake *FakeProjectcalicoV3
}

var felixconfigurationsResource = schema.GroupVersionResource{Group: "projectcalico.org", Version: "v3", Resource: "felixconfigurations"}

var felixconfigurationsKind = schema.GroupVersionKind{Group: "projectcalico.org", Version: "v3", Kind: "FelixConfiguration"}

// Get takes name of the felixConfiguration, and returns the corresponding felixConfiguration object, and an error if there is any.
func (c *FakeFelixConfigurations) Get(ctx context.Context, name string, options v1.GetOptions) (result *v3.FelixConfiguration, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootGetAction(felixconfigurationsResource, name), &v3.FelixConfiguration{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v3.FelixConfiguration), err
}

// List takes label and field selectors, and returns the list of FelixConfigurations that match those selectors.
func (c *FakeFelixConfigurations) List(ctx context.Context, opts v1.ListOptions) (result *v3.FelixConfigurationList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootListAction(felixconfigurationsResource, felixconfigurationsKind, opts), &v3.FelixConfigurationList{})
	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v3.FelixConfigurationList{ListMeta: obj.(*v3.FelixConfigurationList).ListMeta}
	for _, item := range obj.(*v3.FelixConfigurationList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested felixConfigurations.
func (c *FakeFelixConfigurations) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchAction(felixconfigurationsResource, opts))
}

// Create takes the representation of a felixConfiguration and creates it.  Returns the server's representation of the felixConfiguration, and an error, if there is any.
func (c *FakeFelixConfigurations) Create(ctx context.Context, felixConfiguration *v3.FelixConfiguration, opts v1.CreateOptions) (result *v3.FelixConfiguration, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateAction(felixconfigurationsResource, felixConfiguration), &v3.FelixConfiguration{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v3.FelixConfiguration), err
}

// Update takes the representation of a felixConfiguration and updates it. Returns the server's representation of the felixConfiguration, and an error, if there is any.
func (c *FakeFelixConfigurations) Update(ctx context.Context, felixConfiguration *v3.FelixConfiguration, opts v1.UpdateOptions) (result *v3.FelixConfiguration, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateAction(felixconfigurationsResource, felixConfiguration), &v3.FelixConfiguration{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v3.FelixConfiguration), err
}

// Delete takes name of the felixConfiguration and deletes it. Returns an error if one occurs.
func (c *FakeFelixConfigurations) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteActionWithOptions(felixconfigurationsResource, name, opts), &v3.FelixConfiguration{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeFelixConfigurations) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewRootDeleteCollectionAction(felixconfigurationsResource, listOpts)

	_, err := c.Fake.Invokes(action, &v3.FelixConfigurationList{})
	return err
}

// Patch applies the patch and returns the patched felixConfiguration.
func (c *FakeFelixConfigurations) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v3.FelixConfiguration, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceAction(felixconfigurationsResource, name, pt, data, subresources...), &v3.FelixConfiguration{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v3.FelixConfiguration), err
}
