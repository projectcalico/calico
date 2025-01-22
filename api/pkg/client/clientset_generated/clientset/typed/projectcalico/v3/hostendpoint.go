// Copyright (c) 2025 Tigera, Inc. All rights reserved.

// Code generated by client-gen. DO NOT EDIT.

package v3

import (
	"context"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	scheme "github.com/projectcalico/api/pkg/client/clientset_generated/clientset/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	gentype "k8s.io/client-go/gentype"
)

// HostEndpointsGetter has a method to return a HostEndpointInterface.
// A group's client should implement this interface.
type HostEndpointsGetter interface {
	HostEndpoints() HostEndpointInterface
}

// HostEndpointInterface has methods to work with HostEndpoint resources.
type HostEndpointInterface interface {
	Create(ctx context.Context, hostEndpoint *v3.HostEndpoint, opts v1.CreateOptions) (*v3.HostEndpoint, error)
	Update(ctx context.Context, hostEndpoint *v3.HostEndpoint, opts v1.UpdateOptions) (*v3.HostEndpoint, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v3.HostEndpoint, error)
	List(ctx context.Context, opts v1.ListOptions) (*v3.HostEndpointList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v3.HostEndpoint, err error)
	HostEndpointExpansion
}

// hostEndpoints implements HostEndpointInterface
type hostEndpoints struct {
	*gentype.ClientWithList[*v3.HostEndpoint, *v3.HostEndpointList]
}

// newHostEndpoints returns a HostEndpoints
func newHostEndpoints(c *ProjectcalicoV3Client) *hostEndpoints {
	return &hostEndpoints{
		gentype.NewClientWithList[*v3.HostEndpoint, *v3.HostEndpointList](
			"hostendpoints",
			c.RESTClient(),
			scheme.ParameterCodec,
			"",
			func() *v3.HostEndpoint { return &v3.HostEndpoint{} },
			func() *v3.HostEndpointList { return &v3.HostEndpointList{} }),
	}
}
