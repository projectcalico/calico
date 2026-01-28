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
	"errors"
	"reflect"
	"strings"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"

	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
)

const (
	IPAMHandleResourceName = "IPAMHandles"
)

func NewIPAMHandleClient(r rest.Interface, group BackingAPIGroup) K8sResourceClient {
	// Create a resource client which manages k8s CRDs.
	rc := customResourceClient{
		restClient:      r,
		resource:        IPAMHandleResourceName,
		k8sResourceType: reflect.TypeOf(libapiv3.IPAMHandle{}),
		k8sListType:     reflect.TypeOf(libapiv3.IPAMHandleList{}),
		kind:            libapiv3.KindIPAMHandle,
		apiGroup:        group,
	}

	if group == BackingAPIGroupV3 {
		// If this is a v3 resource, then we need to use the v3 API types, as they differ.
		rc.k8sResourceType = reflect.TypeOf(v3.IPAMHandle{})
		rc.k8sListType = reflect.TypeOf(v3.IPAMHandleList{})
	}

	return &ipamHandleClient{
		rc: rc,
		v3: group == BackingAPIGroupV3,
	}
}

// affinityHandleClient implements the api.Client interface for IPAMHandle objects. It
// handles the translation between v1 objects understood by the IPAM codebase in lib/ipam,
// and the CRDs which are used to actually store the data in the Kubernetes API.
// It uses a customK8sResourceClient under the covers to perform CRUD operations on
// kubernetes CRDs.
type ipamHandleClient struct {
	rc customResourceClient
	v3 bool
}

// toV1 converts a v3 KVPair to a v1 KVPair, which is used by the IPAM codebase.
func (c *ipamHandleClient) toV1(kvpv3 *model.KVPair) *model.KVPair {
	var handleID string
	var block map[string]int
	var del bool
	var uid types.UID

	if c.v3 {
		v3Handle := kvpv3.Value.(*v3.IPAMHandle)
		handleID = v3Handle.Spec.HandleID
		block = v3Handle.Spec.Block
		del = v3Handle.Spec.Deleted
		uid = v3Handle.UID
	} else {
		v3Handle := kvpv3.Value.(*libapiv3.IPAMHandle)
		handleID = v3Handle.Spec.HandleID
		block = v3Handle.Spec.Block
		del = v3Handle.Spec.Deleted
		uid = v3Handle.UID
	}

	return &model.KVPair{
		Key: model.IPAMHandleKey{HandleID: handleID},
		Value: &model.IPAMHandle{
			HandleID: handleID,
			Block:    block,
			Deleted:  del,
		},
		Revision: kvpv3.Revision,
		UID:      &uid,
	}
}

func (c *ipamHandleClient) parseKey(k model.Key) string {
	return strings.ToLower(k.(model.IPAMHandleKey).HandleID)
}

// toV3 converts a v1 KVPair to a v3 KVPair, which is used for the Kubernetes API.
func (c *ipamHandleClient) toV3(kvpv1 *model.KVPair) *model.KVPair {
	name := c.parseKey(kvpv1.Key)
	handle := kvpv1.Key.(model.IPAMHandleKey).HandleID
	block := kvpv1.Value.(*model.IPAMHandle).Block
	del := kvpv1.Value.(*model.IPAMHandle).Deleted

	var uid types.UID
	if kvpv1.UID != nil {
		uid = *kvpv1.UID
	}

	var val any
	val = &libapiv3.IPAMHandle{
		TypeMeta: metav1.TypeMeta{
			Kind:       libapiv3.KindIPAMHandle,
			APIVersion: "crd.projectcalico.org/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			ResourceVersion: kvpv1.Revision,
			UID:             uid,
		},
		Spec: libapiv3.IPAMHandleSpec{
			HandleID: handle,
			Block:    block,
			Deleted:  del,
		},
	}

	if c.v3 {
		// If this is a v3 resource, then we need to use the v3 API version.
		val = &v3.IPAMHandle{
			TypeMeta: metav1.TypeMeta{
				Kind:       libapiv3.KindIPAMHandle,
				APIVersion: "projectcalico.org/v3",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:            name,
				ResourceVersion: kvpv1.Revision,
				UID:             uid,
			},
			Spec: v3.IPAMHandleSpec{
				HandleID: handle,
				Block:    block,
				Deleted:  del,
			},
		}
	}

	return &model.KVPair{
		Key: model.ResourceKey{
			Name: name,
			Kind: libapiv3.KindIPAMHandle,
		},
		Value:    val,
		Revision: kvpv1.Revision,
	}
}

func (c *ipamHandleClient) Create(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	nkvp := c.toV3(kvp)
	kvp, err := c.rc.Create(ctx, nkvp)
	if err != nil {
		return nil, err
	}
	return c.toV1(kvp), nil
}

func (c *ipamHandleClient) Update(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	nkvp := c.toV3(kvp)
	kvp, err := c.rc.Update(ctx, nkvp)
	if err != nil {
		return nil, err
	}
	return c.toV1(kvp), nil
}

func (c *ipamHandleClient) DeleteKVP(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	// We need to mark as deleted first, since the Kubernetes API doesn't support
	// compare-and-delete. This update operation allows us to eliminate races with other clients.
	name := c.parseKey(kvp.Key)
	kvp.Value.(*model.IPAMHandle).Deleted = true
	v1kvp, err := c.Update(ctx, kvp)
	if err != nil {
		return nil, err
	}

	// Now actually delete the object.
	k := model.ResourceKey{Name: name, Kind: libapiv3.KindIPAMHandle}
	kvp, err = c.rc.Delete(ctx, k, v1kvp.Revision, kvp.UID)
	if err != nil {
		return nil, err
	}
	return c.toV1(kvp), nil
}

func (c *ipamHandleClient) Delete(ctx context.Context, key model.Key, revision string, uid *types.UID) (*model.KVPair, error) {
	// Delete should not be used for handles, since we need the object UID for correctness.
	log.Warn("Operation Delete is not supported on IPAMHandle type")
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: key,
		Operation:  "Delete",
	}
}

func (c *ipamHandleClient) Get(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	name := c.parseKey(key)
	k := model.ResourceKey{Name: name, Kind: libapiv3.KindIPAMHandle}
	kvp, err := c.rc.Get(ctx, k, revision)
	if err != nil {
		return nil, err
	}

	// Convert it to v1.
	v1kvp := c.toV1(kvp)

	// If this object has been marked as deleted, then we need to clean it up and
	// return not found.
	if v1kvp.Value.(*model.IPAMHandle).Deleted {
		if _, err := c.DeleteKVP(ctx, v1kvp); err != nil {
			return nil, err
		}
		return nil, cerrors.ErrorResourceDoesNotExist{Err: errors.New("resource was deleted"), Identifier: key}
	}

	return v1kvp, nil
}

func (c *ipamHandleClient) List(ctx context.Context, list model.ListInterface, revision string) (*model.KVPairList, error) {
	l := model.ResourceListOptions{Kind: libapiv3.KindIPAMHandle}
	v3list, err := c.rc.List(ctx, l, revision)
	if err != nil {
		return nil, err
	}

	kvpl := &model.KVPairList{
		KVPairs:  []*model.KVPair{},
		Revision: v3list.Revision,
	}
	for _, i := range v3list.KVPairs {
		v1kvp := c.toV1(i)
		kvpl.KVPairs = append(kvpl.KVPairs, v1kvp)
	}
	return kvpl, nil
}

func (c *ipamHandleClient) Watch(ctx context.Context, list model.ListInterface, options api.WatchOptions) (api.WatchInterface, error) {
	log.Warn("Operation Watch is not supported on IPAMHandle type")
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: list,
		Operation:  "Watch",
	}
}

func (c *ipamHandleClient) EnsureInitialized() error {
	return nil
}
