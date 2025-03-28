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

// BlockAffinitiesGetter has a method to return a BlockAffinityInterface.
// A group's client should implement this interface.
type BlockAffinitiesGetter interface {
	BlockAffinities() BlockAffinityInterface
}

// BlockAffinityInterface has methods to work with BlockAffinity resources.
type BlockAffinityInterface interface {
	Create(ctx context.Context, blockAffinity *projectcalicov3.BlockAffinity, opts v1.CreateOptions) (*projectcalicov3.BlockAffinity, error)
	Update(ctx context.Context, blockAffinity *projectcalicov3.BlockAffinity, opts v1.UpdateOptions) (*projectcalicov3.BlockAffinity, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*projectcalicov3.BlockAffinity, error)
	List(ctx context.Context, opts v1.ListOptions) (*projectcalicov3.BlockAffinityList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *projectcalicov3.BlockAffinity, err error)
	BlockAffinityExpansion
}

// blockAffinities implements BlockAffinityInterface
type blockAffinities struct {
	*gentype.ClientWithList[*projectcalicov3.BlockAffinity, *projectcalicov3.BlockAffinityList]
}

// newBlockAffinities returns a BlockAffinities
func newBlockAffinities(c *ProjectcalicoV3Client) *blockAffinities {
	return &blockAffinities{
		gentype.NewClientWithList[*projectcalicov3.BlockAffinity, *projectcalicov3.BlockAffinityList](
			"blockaffinities",
			c.RESTClient(),
			scheme.ParameterCodec,
			"",
			func() *projectcalicov3.BlockAffinity { return &projectcalicov3.BlockAffinity{} },
			func() *projectcalicov3.BlockAffinityList { return &projectcalicov3.BlockAffinityList{} },
		),
	}
}
