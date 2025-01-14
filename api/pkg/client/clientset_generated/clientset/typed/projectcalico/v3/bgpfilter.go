// Copyright (c) 2025 Tigera, Inc. All rights reserved.

// Code generated by client-gen. DO NOT EDIT.

package v3

import (
	"context"
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	scheme "github.com/projectcalico/api/pkg/client/clientset_generated/clientset/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// BGPFiltersGetter has a method to return a BGPFilterInterface.
// A group's client should implement this interface.
type BGPFiltersGetter interface {
	BGPFilters() BGPFilterInterface
}

// BGPFilterInterface has methods to work with BGPFilter resources.
type BGPFilterInterface interface {
	Create(ctx context.Context, bGPFilter *v3.BGPFilter, opts v1.CreateOptions) (*v3.BGPFilter, error)
	Update(ctx context.Context, bGPFilter *v3.BGPFilter, opts v1.UpdateOptions) (*v3.BGPFilter, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v3.BGPFilter, error)
	List(ctx context.Context, opts v1.ListOptions) (*v3.BGPFilterList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v3.BGPFilter, err error)
	BGPFilterExpansion
}

// bGPFilters implements BGPFilterInterface
type bGPFilters struct {
	client rest.Interface
}

// newBGPFilters returns a BGPFilters
func newBGPFilters(c *ProjectcalicoV3Client) *bGPFilters {
	return &bGPFilters{
		client: c.RESTClient(),
	}
}

// Get takes name of the bGPFilter, and returns the corresponding bGPFilter object, and an error if there is any.
func (c *bGPFilters) Get(ctx context.Context, name string, options v1.GetOptions) (result *v3.BGPFilter, err error) {
	result = &v3.BGPFilter{}
	err = c.client.Get().
		Resource("bgpfilters").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of BGPFilters that match those selectors.
func (c *bGPFilters) List(ctx context.Context, opts v1.ListOptions) (result *v3.BGPFilterList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v3.BGPFilterList{}
	err = c.client.Get().
		Resource("bgpfilters").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested bGPFilters.
func (c *bGPFilters) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Resource("bgpfilters").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a bGPFilter and creates it.  Returns the server's representation of the bGPFilter, and an error, if there is any.
func (c *bGPFilters) Create(ctx context.Context, bGPFilter *v3.BGPFilter, opts v1.CreateOptions) (result *v3.BGPFilter, err error) {
	result = &v3.BGPFilter{}
	err = c.client.Post().
		Resource("bgpfilters").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(bGPFilter).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a bGPFilter and updates it. Returns the server's representation of the bGPFilter, and an error, if there is any.
func (c *bGPFilters) Update(ctx context.Context, bGPFilter *v3.BGPFilter, opts v1.UpdateOptions) (result *v3.BGPFilter, err error) {
	result = &v3.BGPFilter{}
	err = c.client.Put().
		Resource("bgpfilters").
		Name(bGPFilter.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(bGPFilter).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the bGPFilter and deletes it. Returns an error if one occurs.
func (c *bGPFilters) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	return c.client.Delete().
		Resource("bgpfilters").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *bGPFilters) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Resource("bgpfilters").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched bGPFilter.
func (c *bGPFilters) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v3.BGPFilter, err error) {
	result = &v3.BGPFilter{}
	err = c.client.Patch(pt).
		Resource("bgpfilters").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}
