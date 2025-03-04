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

// StagedGlobalNetworkPoliciesGetter has a method to return a StagedGlobalNetworkPolicyInterface.
// A group's client should implement this interface.
type StagedGlobalNetworkPoliciesGetter interface {
	StagedGlobalNetworkPolicies() StagedGlobalNetworkPolicyInterface
}

// StagedGlobalNetworkPolicyInterface has methods to work with StagedGlobalNetworkPolicy resources.
type StagedGlobalNetworkPolicyInterface interface {
	Create(ctx context.Context, stagedGlobalNetworkPolicy *projectcalicov3.StagedGlobalNetworkPolicy, opts v1.CreateOptions) (*projectcalicov3.StagedGlobalNetworkPolicy, error)
	Update(ctx context.Context, stagedGlobalNetworkPolicy *projectcalicov3.StagedGlobalNetworkPolicy, opts v1.UpdateOptions) (*projectcalicov3.StagedGlobalNetworkPolicy, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*projectcalicov3.StagedGlobalNetworkPolicy, error)
	List(ctx context.Context, opts v1.ListOptions) (*projectcalicov3.StagedGlobalNetworkPolicyList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *projectcalicov3.StagedGlobalNetworkPolicy, err error)
	StagedGlobalNetworkPolicyExpansion
}

// stagedGlobalNetworkPolicies implements StagedGlobalNetworkPolicyInterface
type stagedGlobalNetworkPolicies struct {
	*gentype.ClientWithList[*projectcalicov3.StagedGlobalNetworkPolicy, *projectcalicov3.StagedGlobalNetworkPolicyList]
}

// newStagedGlobalNetworkPolicies returns a StagedGlobalNetworkPolicies
func newStagedGlobalNetworkPolicies(c *ProjectcalicoV3Client) *stagedGlobalNetworkPolicies {
	return &stagedGlobalNetworkPolicies{
		gentype.NewClientWithList[*projectcalicov3.StagedGlobalNetworkPolicy, *projectcalicov3.StagedGlobalNetworkPolicyList](
			"stagedglobalnetworkpolicies",
			c.RESTClient(),
			scheme.ParameterCodec,
			"",
			func() *projectcalicov3.StagedGlobalNetworkPolicy { return &projectcalicov3.StagedGlobalNetworkPolicy{} },
			func() *projectcalicov3.StagedGlobalNetworkPolicyList {
				return &projectcalicov3.StagedGlobalNetworkPolicyList{}
			},
		),
	}
}
