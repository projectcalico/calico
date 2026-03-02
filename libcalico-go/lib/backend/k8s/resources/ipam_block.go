// Copyright (c) 2019 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package resources

import (
	"context"
	"fmt"
	"reflect"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

const (
	IPAMBlockResourceName = "IPAMBlocks"
)

func NewIPAMBlockClient(r rest.Interface, group BackingAPIGroup) K8sResourceClient {
	// Create a resource client which manages k8s CRDs.
	rc := customResourceClient{
		restClient:      r,
		resource:        IPAMBlockResourceName,
		k8sResourceType: reflect.TypeFor[internalapi.IPAMBlock](),
		k8sListType:     reflect.TypeFor[internalapi.IPAMBlockList](),
		kind:            internalapi.KindIPAMBlock,
		apiGroup:        group,
	}

	if group == BackingAPIGroupV3 {
		// If this is a v3 resource, then we need to use the v3 API types, as they differ.
		rc.k8sResourceType = reflect.TypeFor[v3.IPAMBlock]()
		rc.k8sListType = reflect.TypeFor[v3.IPAMBlockList]()
	}

	return &ipamBlockClient{
		rc: rc,
		v3: group == BackingAPIGroupV3,
	}
}

// ipamBlockClient implements the api.Client interface for IPAMBlocks. It handles the translation between
// v1 objects understood by the IPAM codebase in lib/ipam, and the CRDs which are used
// to actually store the data in the Kubernetes API. It uses a customK8sResourceClient under
// the covers to perform CRUD operations on kubernetes CRDs.
type ipamBlockClient struct {
	rc customResourceClient
	v3 bool
}

func (c *ipamBlockClient) Create(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	nkvp := c.IPAMBlockV1toV3(kvp)
	b, err := c.rc.Create(ctx, nkvp)
	if err != nil {
		return nil, err
	}
	v1kvp, err := c.IPAMBlockV3toV1(b)
	if err != nil {
		return nil, err
	}
	return v1kvp, nil
}

func (c *ipamBlockClient) Update(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	nkvp := c.IPAMBlockV1toV3(kvp)
	b, err := c.rc.Update(ctx, nkvp)
	if err != nil {
		return nil, err
	}
	v1kvp, err := c.IPAMBlockV3toV1(b)
	if err != nil {
		return nil, err
	}
	return v1kvp, nil
}

func (c *ipamBlockClient) DeleteKVP(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	// We need to mark as deleted first, since the Kubernetes API doesn't support
	// compare-and-delete. This update operation allows us to eliminate races with other clients.
	name, _ := parseKey(kvp.Key)
	kvp.Value.(*model.AllocationBlock).Deleted = true
	v1kvp, err := c.Update(ctx, kvp)
	if err != nil {
		return nil, err
	}

	// Now actually delete the object.
	k := model.ResourceKey{Name: name, Kind: internalapi.KindIPAMBlock}
	kvp, err = c.rc.Delete(ctx, k, v1kvp.Revision, kvp.UID)
	if err != nil {
		return nil, err
	}
	return c.IPAMBlockV3toV1(kvp)
}

func (c *ipamBlockClient) Delete(ctx context.Context, key model.Key, revision string, uid *types.UID) (*model.KVPair, error) {
	// Delete should not be used for blocks, since we need the object UID for correctness.
	log.Warn("Operation Delete is not supported on IPAMBlock type - use DeleteKVP")
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: key,
		Operation:  "Delete",
	}
}

func (c *ipamBlockClient) Get(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	// Get the object.
	name, _ := parseKey(key)
	k := model.ResourceKey{Name: name, Kind: internalapi.KindIPAMBlock}
	kvp, err := c.rc.Get(ctx, k, revision)
	if err != nil {
		return nil, err
	}

	// Convert it back to V1 format.
	v1kvp, err := c.IPAMBlockV3toV1(kvp)
	if err != nil {
		return nil, err
	}

	// If this object has been marked as deleted, then we need to clean it up and
	// return not found.
	if v1kvp.Value.(*model.AllocationBlock).Deleted {
		if _, err := c.DeleteKVP(ctx, v1kvp); err != nil {
			return nil, err
		}
		return nil, cerrors.ErrorResourceDoesNotExist{Err: fmt.Errorf("Resource was deleted"), Identifier: key}
	}

	return v1kvp, nil
}

func (c *ipamBlockClient) List(ctx context.Context, list model.ListInterface, revision string) (*model.KVPairList, error) {
	l := model.ResourceListOptions{Kind: internalapi.KindIPAMBlock}
	v3list, err := c.rc.List(ctx, l, revision)
	if err != nil {
		return nil, err
	}

	kvpl := &model.KVPairList{
		KVPairs:  []*model.KVPair{},
		Revision: v3list.Revision,
	}
	for _, i := range v3list.KVPairs {
		v1kvp, err := c.IPAMBlockV3toV1(i)
		if err != nil {
			return nil, err
		}
		kvpl.KVPairs = append(kvpl.KVPairs, v1kvp)
	}
	return kvpl, nil
}

func (c *ipamBlockClient) Watch(ctx context.Context, list model.ListInterface, options api.WatchOptions) (api.WatchInterface, error) {
	resl := model.ResourceListOptions{Kind: internalapi.KindIPAMBlock}
	k8sWatchClient := cache.NewListWatchFromClient(c.rc.restClient, c.rc.resource, "", fields.Everything())
	k8sOpts := watchOptionsToK8sListOptions(options)
	k8sWatch, err := k8sWatchClient.WatchFunc(k8sOpts)
	if err != nil {
		return nil, K8sErrorToCalico(err, list)
	}
	toKVPair := func(r Resource) (*model.KVPair, error) {
		conv, err := c.rc.convertResourceToKVPair(r)
		if err != nil {
			return nil, err
		}
		return c.IPAMBlockV3toV1(conv)
	}

	return newK8sWatcherConverter(ctx, resl.Kind+" (custom)", toKVPair, k8sWatch), nil
}

// EnsureInitialized is a no-op since the CRD should be
// initialized in advance.
func (c *ipamBlockClient) EnsureInitialized() error {
	return nil
}

func (c *ipamBlockClient) IPAMBlockV3toV1(kvpv3 *model.KVPair) (*model.KVPair, error) {
	switch kvpv3.Value.(type) {
	case *v3.IPAMBlock:
		cidrStr := kvpv3.Value.(*v3.IPAMBlock).Spec.CIDR
		_, cidr, err := net.ParseCIDR(cidrStr)
		if err != nil {
			return nil, err
		}

		ab := kvpv3.Value.(*v3.IPAMBlock)

		// Convert attributes.
		attrs := []model.AllocationAttribute{}
		for _, a := range ab.Spec.Attributes {
			attrs = append(attrs, model.AllocationAttribute{
				HandleID:            a.HandleID,
				ActiveOwnerAttrs:    a.ActiveOwnerAttrs,
				AlternateOwnerAttrs: a.AlternateOwnerAttrs,
			})
		}

		return &model.KVPair{
			Key: model.BlockKey{
				CIDR: *cidr,
			},
			Value: &model.AllocationBlock{
				CIDR:                        *cidr,
				Affinity:                    ab.Spec.Affinity,
				AffinityClaimTime:           ab.Spec.AffinityClaimTime,
				Allocations:                 ab.Spec.Allocations,
				Unallocated:                 ab.Spec.Unallocated,
				Attributes:                  attrs,
				Deleted:                     ab.Spec.Deleted,
				SequenceNumber:              ab.Spec.SequenceNumber,
				SequenceNumberForAllocation: ab.Spec.SequenceNumberForAllocation,
			},
			Revision: kvpv3.Revision,
			UID:      &ab.UID,
		}, nil
	case *internalapi.IPAMBlock:
		cidrStr := kvpv3.Value.(*internalapi.IPAMBlock).Spec.CIDR
		_, cidr, err := net.ParseCIDR(cidrStr)
		if err != nil {
			return nil, err
		}

		ab := kvpv3.Value.(*internalapi.IPAMBlock)

		// Convert attributes.
		attrs := []model.AllocationAttribute{}
		for _, a := range ab.Spec.Attributes {
			attrs = append(attrs, model.AllocationAttribute{
				HandleID:            a.HandleID,
				ActiveOwnerAttrs:    a.ActiveOwnerAttrs,
				AlternateOwnerAttrs: a.AlternateOwnerAttrs,
			})
		}

		return &model.KVPair{
			Key: model.BlockKey{
				CIDR: *cidr,
			},
			Value: &model.AllocationBlock{
				CIDR:                        *cidr,
				Affinity:                    ab.Spec.Affinity,
				AffinityClaimTime:           ab.Spec.AffinityClaimTime,
				Allocations:                 ab.Spec.Allocations,
				Unallocated:                 ab.Spec.Unallocated,
				Attributes:                  attrs,
				Deleted:                     ab.Spec.Deleted,
				SequenceNumber:              ab.Spec.SequenceNumber,
				SequenceNumberForAllocation: ab.Spec.SequenceNumberForAllocation,
			},
			Revision: kvpv3.Revision,
			UID:      &ab.UID,
		}, nil
	}
	return nil, fmt.Errorf("unexpected type %T for IPAMBlock", kvpv3.Value)
}

func (c *ipamBlockClient) IPAMBlockV1toV3(kvpv1 *model.KVPair) *model.KVPair {
	if c.v3 {
		name, cidr := parseKey(kvpv1.Key)

		ab := kvpv1.Value.(*model.AllocationBlock)

		// Convert attributes.
		attrs := []v3.AllocationAttribute{}
		for _, a := range ab.Attributes {
			attrs = append(attrs, v3.AllocationAttribute{
				HandleID:            a.HandleID,
				ActiveOwnerAttrs:    a.ActiveOwnerAttrs,
				AlternateOwnerAttrs: a.AlternateOwnerAttrs,
			})
		}

		apiVersion := "projectcalico.org/v3"

		return &model.KVPair{
			Key: model.ResourceKey{
				Name: name,
				Kind: internalapi.KindIPAMBlock,
			},
			Value: &v3.IPAMBlock{
				TypeMeta: metav1.TypeMeta{
					Kind:       internalapi.KindIPAMBlock,
					APIVersion: apiVersion,
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:            name,
					ResourceVersion: kvpv1.Revision,
				},
				Spec: v3.IPAMBlockSpec{
					CIDR:                        cidr,
					Allocations:                 ab.Allocations,
					Unallocated:                 ab.Unallocated,
					Affinity:                    ab.Affinity,
					AffinityClaimTime:           ab.AffinityClaimTime,
					Attributes:                  attrs,
					Deleted:                     ab.Deleted,
					SequenceNumber:              ab.SequenceNumber,
					SequenceNumberForAllocation: ab.SequenceNumberForAllocation,
				},
			},
			Revision: kvpv1.Revision,
		}
	} else {
		name, cidr := parseKey(kvpv1.Key)

		ab := kvpv1.Value.(*model.AllocationBlock)

		// Convert attributes.
		attrs := []internalapi.AllocationAttribute{}
		for _, a := range ab.Attributes {
			attrs = append(attrs, internalapi.AllocationAttribute{
				HandleID:            a.HandleID,
				ActiveOwnerAttrs:    a.ActiveOwnerAttrs,
				AlternateOwnerAttrs: a.AlternateOwnerAttrs,
			})
		}

		apiVersion := "crd.projectcalico.org/v1"

		return &model.KVPair{
			Key: model.ResourceKey{
				Name: name,
				Kind: internalapi.KindIPAMBlock,
			},
			Value: &internalapi.IPAMBlock{
				TypeMeta: metav1.TypeMeta{
					Kind:       internalapi.KindIPAMBlock,
					APIVersion: apiVersion,
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:            name,
					ResourceVersion: kvpv1.Revision,
				},
				Spec: internalapi.IPAMBlockSpec{
					CIDR:                        cidr,
					Allocations:                 ab.Allocations,
					Unallocated:                 ab.Unallocated,
					Affinity:                    ab.Affinity,
					AffinityClaimTime:           ab.AffinityClaimTime,
					Attributes:                  attrs,
					Deleted:                     ab.Deleted,
					SequenceNumber:              ab.SequenceNumber,
					SequenceNumberForAllocation: ab.SequenceNumberForAllocation,
				},
			},
			Revision: kvpv1.Revision,
		}
	}
}

func parseKey(k model.Key) (name, cidr string) {
	cidr = fmt.Sprintf("%s", k.(model.BlockKey).CIDR)
	name = names.CIDRToName(k.(model.BlockKey).CIDR)
	return
}
