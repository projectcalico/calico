// Copyright (c) 2025 Tigera, Inc. All rights reserved.

// Code generated by client-gen. DO NOT EDIT.

package v3

import (
	context "context"

	projectcalicov3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	scheme "github.com/projectcalico/api/pkg/client/clientset_generated/clientset/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	gentype "k8s.io/client-go/gentype"
)

// CalicoNodeStatusesGetter has a method to return a CalicoNodeStatusInterface.
// A group's client should implement this interface.
type CalicoNodeStatusesGetter interface {
	CalicoNodeStatuses() CalicoNodeStatusInterface
}

// CalicoNodeStatusInterface has methods to work with CalicoNodeStatus resources.
type CalicoNodeStatusInterface interface {
	Create(ctx context.Context, calicoNodeStatus *projectcalicov3.CalicoNodeStatus, opts v1.CreateOptions) (*projectcalicov3.CalicoNodeStatus, error)
	Update(ctx context.Context, calicoNodeStatus *projectcalicov3.CalicoNodeStatus, opts v1.UpdateOptions) (*projectcalicov3.CalicoNodeStatus, error)
	// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
	UpdateStatus(ctx context.Context, calicoNodeStatus *projectcalicov3.CalicoNodeStatus, opts v1.UpdateOptions) (*projectcalicov3.CalicoNodeStatus, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*projectcalicov3.CalicoNodeStatus, error)
	List(ctx context.Context, opts v1.ListOptions) (*projectcalicov3.CalicoNodeStatusList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *projectcalicov3.CalicoNodeStatus, err error)
	CalicoNodeStatusExpansion
}

// calicoNodeStatuses implements CalicoNodeStatusInterface
type calicoNodeStatuses struct {
	*gentype.ClientWithList[*projectcalicov3.CalicoNodeStatus, *projectcalicov3.CalicoNodeStatusList]
}

// newCalicoNodeStatuses returns a CalicoNodeStatuses
func newCalicoNodeStatuses(c *ProjectcalicoV3Client) *calicoNodeStatuses {
	return &calicoNodeStatuses{
		gentype.NewClientWithList[*projectcalicov3.CalicoNodeStatus, *projectcalicov3.CalicoNodeStatusList](
			"caliconodestatuses",
			c.RESTClient(),
			scheme.ParameterCodec,
			"",
			func() *projectcalicov3.CalicoNodeStatus { return &projectcalicov3.CalicoNodeStatus{} },
			func() *projectcalicov3.CalicoNodeStatusList { return &projectcalicov3.CalicoNodeStatusList{} },
		),
	}
}
