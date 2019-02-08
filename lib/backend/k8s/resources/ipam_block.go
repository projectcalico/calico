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

	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/libcalico-go/lib/errors"
	"github.com/projectcalico/libcalico-go/lib/names"
	"github.com/projectcalico/libcalico-go/lib/net"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	IPAMBlockResourceName = "IPAMBlocks"
	IPAMBlockCRDName      = "ipamblocks.crd.projectcalico.org"
)

func NewIPAMBlockClient(c *kubernetes.Clientset, r *rest.RESTClient) K8sResourceClient {
	// Create a resource client which manages k8s CRDs.
	rc := customK8sResourceClient{
		clientSet:       c,
		restClient:      r,
		name:            IPAMBlockCRDName,
		resource:        IPAMBlockResourceName,
		description:     "Calico IPAM blocks",
		k8sResourceType: reflect.TypeOf(apiv3.IPAMBlock{}),
		k8sResourceTypeMeta: metav1.TypeMeta{
			Kind:       apiv3.KindIPAMBlock,
			APIVersion: apiv3.GroupVersionCurrent,
		},
		k8sListType:  reflect.TypeOf(apiv3.IPAMBlockList{}),
		resourceKind: apiv3.KindIPAMBlock,
	}

	return &ipamBlockClient{rc: rc}
}

// ipamBlockClient implements the api.Client interface for IPAMBlocks. It handles the translation between
// v1 objects understood by the IPAM codebase in lib/ipam, and the CRDs which are used
// to actually store the data in the Kubernetes API.
// It uses a customK8sResourceClient under the covers to perform CRUD operations on
// kubernetes CRDs.
type ipamBlockClient struct {
	rc customK8sResourceClient
}

func (c ipamBlockClient) toV1(kvpv3 *model.KVPair) (*model.KVPair, error) {
	cidrStr := kvpv3.Value.(*apiv3.IPAMBlock).Annotations["projectcalico.org/cidr"]
	_, cidr, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return nil, err
	}

	ab := kvpv3.Value.(*apiv3.IPAMBlock)

	// The CRD needs ints, not *int, so convert here.
	allocations := []*int{}
	for _, a := range ab.Spec.Allocations {
		if a == -1 {
			allocations = append(allocations, nil)
		} else {
			a2 := a
			allocations = append(allocations, &a2)
		}
	}

	// Convert attributes.
	attrs := []model.AllocationAttribute{}
	for _, a := range ab.Spec.Attributes {
		attrs = append(attrs, model.AllocationAttribute{
			AttrPrimary:   a.AttrPrimary,
			AttrSecondary: a.AttrSecondary,
		})
	}

	return &model.KVPair{
		Key: model.BlockKey{
			CIDR: *cidr,
		},
		Value: &model.AllocationBlock{
			CIDR:           *cidr,
			Affinity:       ab.Spec.Affinity,
			StrictAffinity: ab.Spec.StrictAffinity,
			Allocations:    allocations,
			Unallocated:    ab.Spec.Unallocated,
			Attributes:     attrs,
			Deleting:       ab.Spec.Deleting,
		},
		Revision: kvpv3.Revision,
		UID:      &ab.UID,
	}, nil
}

func (c ipamBlockClient) parseKey(k model.Key) (name, cidr string) {
	cidr = fmt.Sprintf("%s", k.(model.BlockKey).CIDR)
	name = names.CIDRToName(k.(model.BlockKey).CIDR)
	return
}

func (c ipamBlockClient) toV3(kvpv1 *model.KVPair) *model.KVPair {
	name, cidr := c.parseKey(kvpv1.Key)

	ab := kvpv1.Value.(*model.AllocationBlock)

	// The CRD needs ints, not *int, so convert here.
	allocations := []int{}
	for _, a := range ab.Allocations {
		if a != nil {
			allocations = append(allocations, *a)
		} else if a == nil {
			allocations = append(allocations, -1)
		}
	}

	// Convert attributes.
	attrs := []apiv3.AllocationAttribute{}
	for _, a := range ab.Attributes {
		attrs = append(attrs, apiv3.AllocationAttribute{
			AttrPrimary:   a.AttrPrimary,
			AttrSecondary: a.AttrSecondary,
		})
	}

	return &model.KVPair{
		Key: model.ResourceKey{
			Name: name,
			Kind: apiv3.KindIPAMBlock,
		},
		Value: &apiv3.IPAMBlock{
			TypeMeta: metav1.TypeMeta{
				Kind:       apiv3.KindIPAMBlock,
				APIVersion: "crd.projectcalico.org/v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:            name,
				ResourceVersion: kvpv1.Revision,
				Annotations: map[string]string{
					"projectcalico.org/cidr": cidr,
				},
			},
			Spec: apiv3.IPAMBlockSpec{
				CIDR:           cidr,
				Allocations:    allocations,
				Unallocated:    ab.Unallocated,
				Affinity:       ab.Affinity,
				StrictAffinity: ab.StrictAffinity,
				Attributes:     attrs,
				Deleting:       ab.Deleting,
			},
		},
		Revision: kvpv1.Revision,
	}
}

func (c *ipamBlockClient) Create(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	nkvp := c.toV3(kvp)
	b, err := c.rc.Create(ctx, nkvp)
	if err != nil {
		return nil, err
	}
	v1nkvp, err := c.toV1(b)
	if err != nil {
		return nil, err
	}
	return v1nkvp, nil
}

func (c *ipamBlockClient) Update(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	nkvp := c.toV3(kvp)
	b, err := c.rc.Update(ctx, nkvp)
	if err != nil {
		return nil, err
	}
	v1nkvp, err := c.toV1(b)
	if err != nil {
		return nil, err
	}
	return v1nkvp, nil
}

func (c *ipamBlockClient) DeleteKVP(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	name, _ := c.parseKey(kvp.Key)
	k := model.ResourceKey{
		Name: name,
		Kind: apiv3.KindIPAMBlock,
	}
	kvp, err := c.rc.Delete(ctx, k, kvp.Revision, kvp.UID)
	if err != nil {
		return nil, err
	}
	v1nkvp, err := c.toV1(kvp)
	if err != nil {
		return nil, err
	}
	return v1nkvp, nil
}

func (c *ipamBlockClient) Delete(ctx context.Context, key model.Key, revision string, uid *types.UID) (*model.KVPair, error) {
	log.Warn("Operation Delete is not supported on IPAMBlock type - use DeleteKVP")
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: key,
		Operation:  "Delete",
	}
}

func (c *ipamBlockClient) Get(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	name, _ := c.parseKey(key)
	k := model.ResourceKey{
		Name: name,
		Kind: apiv3.KindIPAMBlock,
	}
	kvp, err := c.rc.Get(ctx, k, revision)
	if err != nil {
		return nil, err
	}
	v1nkvp, err := c.toV1(kvp)
	if err != nil {
		return nil, err
	}
	return v1nkvp, nil
}

func (c *ipamBlockClient) List(ctx context.Context, list model.ListInterface, revision string) (*model.KVPairList, error) {
	l := model.ResourceListOptions{Kind: apiv3.KindIPAMBlock}
	v3list, err := c.rc.List(ctx, l, revision)
	if err != nil {
		return nil, err
	}

	kvpl := &model.KVPairList{KVPairs: []*model.KVPair{}}
	for _, i := range v3list.KVPairs {
		v1kvp, err := c.toV1(i)
		if err != nil {
			return nil, err
		}
		kvpl.KVPairs = append(kvpl.KVPairs, v1kvp)
	}
	return kvpl, nil
}

func (c *ipamBlockClient) Watch(ctx context.Context, list model.ListInterface, revision string) (api.WatchInterface, error) {
	log.Warn("Operation Watch is not supported on IPAMBlock type")
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: list,
		Operation:  "Watch",
	}
}

// EnsureInitialized is a no-op since the CRD should be
// initialized in advance.
func (c *ipamBlockClient) EnsureInitialized() error {
	return nil
}
