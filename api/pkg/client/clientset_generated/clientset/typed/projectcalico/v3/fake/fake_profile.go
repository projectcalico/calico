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

// FakeProfiles implements ProfileInterface
type FakeProfiles struct {
	Fake *FakeProjectcalicoV3
}

var profilesResource = v3.SchemeGroupVersion.WithResource("profiles")

var profilesKind = v3.SchemeGroupVersion.WithKind("Profile")

// Get takes name of the profile, and returns the corresponding profile object, and an error if there is any.
func (c *FakeProfiles) Get(ctx context.Context, name string, options v1.GetOptions) (result *v3.Profile, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootGetAction(profilesResource, name), &v3.Profile{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v3.Profile), err
}

// List takes label and field selectors, and returns the list of Profiles that match those selectors.
func (c *FakeProfiles) List(ctx context.Context, opts v1.ListOptions) (result *v3.ProfileList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootListAction(profilesResource, profilesKind, opts), &v3.ProfileList{})
	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v3.ProfileList{ListMeta: obj.(*v3.ProfileList).ListMeta}
	for _, item := range obj.(*v3.ProfileList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested profiles.
func (c *FakeProfiles) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchAction(profilesResource, opts))
}

// Create takes the representation of a profile and creates it.  Returns the server's representation of the profile, and an error, if there is any.
func (c *FakeProfiles) Create(ctx context.Context, profile *v3.Profile, opts v1.CreateOptions) (result *v3.Profile, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateAction(profilesResource, profile), &v3.Profile{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v3.Profile), err
}

// Update takes the representation of a profile and updates it. Returns the server's representation of the profile, and an error, if there is any.
func (c *FakeProfiles) Update(ctx context.Context, profile *v3.Profile, opts v1.UpdateOptions) (result *v3.Profile, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateAction(profilesResource, profile), &v3.Profile{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v3.Profile), err
}

// Delete takes name of the profile and deletes it. Returns an error if one occurs.
func (c *FakeProfiles) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteActionWithOptions(profilesResource, name, opts), &v3.Profile{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeProfiles) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewRootDeleteCollectionAction(profilesResource, listOpts)

	_, err := c.Fake.Invokes(action, &v3.ProfileList{})
	return err
}

// Patch applies the patch and returns the patched profile.
func (c *FakeProfiles) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v3.Profile, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceAction(profilesResource, name, pt, data, subresources...), &v3.Profile{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v3.Profile), err
}
