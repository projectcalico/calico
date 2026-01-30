// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.

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

	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
)

const (
	BlockAffinityResourceName = "BlockAffinities"
)

// NewBlockAffinityClientV3 returns a new client for managing BlockAffinity resources, as used by the
// libcalico-go/lib/clientv3 code.
func NewBlockAffinityClientV3(r rest.Interface, group BackingAPIGroup) K8sResourceClient {
	// Create a resource client which manages k8s CRDs.
	rc := customResourceClient{
		restClient:       r,
		resource:         BlockAffinityResourceName,
		k8sResourceType:  reflect.TypeOf(libapiv3.BlockAffinity{}),
		k8sListType:      reflect.TypeOf(libapiv3.BlockAffinityList{}),
		kind:             v3.KindBlockAffinity,
		versionconverter: ipamAffinityVersionConverter{},
		apiGroup:         group,
	}

	if group == BackingAPIGroupV3 {
		// If this is a v3 resource, then we need to use the v3 API types, as they
		// differ.
		rc.k8sResourceType = reflect.TypeOf(v3.BlockAffinity{})
		rc.k8sListType = reflect.TypeOf(v3.BlockAffinityList{})
	}

	return &blockAffinityClientV3{
		rc:      rc,
		crdIsV3: group == BackingAPIGroupV3,
	}
}

type blockAffinityClientV3 struct {
	rc      customResourceClient
	crdIsV3 bool
}

// ipamAffinityVersionConverter handles converstion between v3 and CRD representations of ipamAffinity.
type ipamAffinityVersionConverter struct{}

// crdToV3 converts the given CRD KVPair into a v3 model representation which can be passed back to the clientv3 code.
func (c ipamAffinityVersionConverter) ConvertFromK8s(r Resource) (Resource, error) {
	switch o := r.(type) {
	case *libapiv3.BlockAffinity:
		// This is a v1 CRD, convert it to the v3 struct expected by clientv3.
		return &v3.BlockAffinity{
			TypeMeta: metav1.TypeMeta{
				Kind:       v3.KindBlockAffinity,
				APIVersion: "projectcalico.org/v3",
			},
			ObjectMeta: o.ObjectMeta,
			Spec: v3.BlockAffinitySpec{
				State:   v3.BlockAffinityState(o.Spec.State),
				Node:    o.Spec.Node,
				Type:    o.Spec.Type,
				CIDR:    o.Spec.CIDR,
				Deleted: o.Spec.Deleted == "true",
			},
		}, nil
	case *v3.BlockAffinity:
		// No conversion necessary - already using v3 CRDs.
		return r, nil
	}
	return nil, fmt.Errorf("invalid type for IPAM configuration KVPair: %T", r)
}

func getBackingAffinityTypeMeta(isV3 bool) metav1.TypeMeta {
	if isV3 {
		// If this is a v3 resource, then we need to use the v3 API version.
		return metav1.TypeMeta{
			Kind:       v3.KindBlockAffinity,
			APIVersion: "projectcalico.org/v3",
		}
	}
	return metav1.TypeMeta{
		Kind:       libapiv3.KindBlockAffinity,
		APIVersion: "crd.projectcalico.org/v1",
	}
}

// buildCRD builds a CRD representation of a BlockAffinity resource with the given parameters.
func buildCRD(state, host, affType, cidr string, deleted bool, name, revision string, isV3 bool) Resource {
	if isV3 {
		// If this is a v3 resource, then we need to use the canonical v3 API version and types.
		ba := &v3.BlockAffinity{
			TypeMeta: getBackingAffinityTypeMeta(isV3),
			ObjectMeta: metav1.ObjectMeta{
				Name:            name,
				ResourceVersion: revision,
			},
			Spec: v3.BlockAffinitySpec{
				State:   v3.BlockAffinityState(state),
				Node:    host,
				Type:    affType,
				CIDR:    cidr,
				Deleted: deleted,
			},
		}
		model.EnsureBlockAffinityLabelsV3(ba)
		return ba
	}

	// If this is a v1 resource, then we need to use the old v1 API version and types.
	ba := &libapiv3.BlockAffinity{
		TypeMeta: getBackingAffinityTypeMeta(isV3),
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			ResourceVersion: revision,
		},
		Spec: libapiv3.BlockAffinitySpec{
			State:   string(state),
			Node:    host,
			Type:    affType,
			CIDR:    cidr,
			Deleted: fmt.Sprintf("%t", deleted),
		},
	}
	model.EnsureBlockAffinityLabels(ba)
	return ba
}

func (c *blockAffinityClientV3) toCRD(kvpv3 *model.KVPair) *model.KVPair {
	// Extract fields from the v3 BlockAffinity.
	obj := kvpv3.Value.(*v3.BlockAffinity)
	name := kvpv3.Key.(model.ResourceKey).Name

	// Build the CRD representation.
	value := buildCRD(
		string(obj.Spec.State),
		obj.Spec.Node,
		obj.Spec.Type,
		obj.Spec.CIDR,
		obj.Spec.Deleted,
		name,
		kvpv3.Revision,
		c.crdIsV3,
	)

	return &model.KVPair{
		Key: model.ResourceKey{
			Name: name,
			Kind: v3.KindBlockAffinity,
		},
		Value:    value,
		Revision: kvpv3.Revision,
	}
}

func (c *blockAffinityClientV3) Create(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	return c.rc.Create(ctx, c.toCRD(kvp))
}

func (c *blockAffinityClientV3) Update(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	return c.rc.Update(ctx, c.toCRD(kvp))
}

func (c *blockAffinityClientV3) DeleteKVP(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	// We need to mark as deleted first, since the Kubernetes API doesn't support
	// compare-and-delete. This update operation allows us to eliminate races with other clients.
	var err error
	nkvp := kvp
	if kvp.Value == nil {
		// Need to check if a value is given since V3 deletes can be made by providing a key only.
		// Look up missing values with the provided key.
		nkvp, err = c.Get(ctx, kvp.Key.(model.ResourceKey), kvp.Revision)
		if err != nil {
			if _, ok := err.(cerrors.ErrorResourceDoesNotExist); ok {
				return nil, fmt.Errorf("Unable to find block affinity. Block affinity may have already been deleted.")
			}
			return nil, fmt.Errorf("Error retrieving block affinity for deletion: %s", err)
		}
	}

	// Pass in the revision for the key-value pair to ensure that deletion occurs for the specified revision,
	// not the revision that is retrieved by the above Get (which should be the most recent).
	if kvp.Revision == "" {
		return nil, fmt.Errorf("Unable to delete block affinity without a resource version")
	}
	nkvp.Revision = kvp.Revision
	nkvp.Value.(*v3.BlockAffinity).Spec.Deleted = true
	nkvp, err = c.Update(ctx, nkvp)
	if err != nil {
		return nil, err
	}

	// Now actually delete the object.
	return c.rc.Delete(ctx, nkvp.Key, nkvp.Revision, &nkvp.Value.(*v3.BlockAffinity).UID)
}

func (c *blockAffinityClientV3) Delete(ctx context.Context, key model.Key, revision string, uid *types.UID) (*model.KVPair, error) {
	// Delete should not be used for affinities, since we need the object UID for correctness.
	log.Warn("Operation Delete is not supported on BlockAffinity type - use DeleteKVP")
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: key,
		Operation:  "Delete",
	}
}

func (c *blockAffinityClientV3) Get(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	return c.rc.Get(ctx, key, revision)
}

func (c *blockAffinityClientV3) List(ctx context.Context, list model.ListInterface, revision string) (*model.KVPairList, error) {
	log.Debugf("Listing v3 block affinities matching %v, revision=%v", list, revision)
	return c.rc.List(ctx, list, revision)
}

func (c *blockAffinityClientV3) toKVPairV3(r Resource) (*model.KVPair, error) {
	return c.rc.convertResourceToKVPair(r)
}

func (c *blockAffinityClientV3) Watch(ctx context.Context, list model.ListInterface, options api.WatchOptions) (api.WatchInterface, error) {
	resl := model.ResourceListOptions{Kind: libapiv3.KindBlockAffinity}
	k8sWatchClient := cache.NewListWatchFromClient(c.rc.restClient, c.rc.resource, "", fields.Everything())
	k8sOpts := watchOptionsToK8sListOptions(options)
	k8sWatch, err := k8sWatchClient.WatchFunc(k8sOpts)
	if err != nil {
		return nil, K8sErrorToCalico(err, list)
	}
	return newK8sWatcherConverter(ctx, resl.Kind+" (custom)", c.toKVPairV3, k8sWatch), nil
}

func (c *blockAffinityClientV3) EnsureInitialized() error {
	return nil
}
