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
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"

	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

const (
	IPAMConfigResourceName   = "IPAMConfigs"
	IPAMConfigResourceNameV3 = "IPAMConfigurations"
)

func NewIPAMConfigClient(r rest.Interface, useV3 bool) K8sResourceClient {
	resource := IPAMConfigResourceName
	if useV3 {
		resource = IPAMConfigResourceNameV3
	}

	rc := customResourceClient{
		restClient:      r,
		resource:        resource,
		k8sResourceType: reflect.TypeOf(libapiv3.IPAMConfiguration{}),
		k8sListType:     reflect.TypeOf(libapiv3.IPAMConfigurationList{}),
		kind:            libapiv3.KindIPAMConfig,
		noTransform:     useV3,
	}

	if useV3 {
		// If this is a v3 resource, then we need to use the v3 API types, as they differ.
		rc.k8sResourceType = reflect.TypeOf(v3.IPAMConfiguration{})
		rc.k8sListType = reflect.TypeOf(v3.IPAMConfigurationList{})
	}

	// TODO: CASEY
	return &ipamConfigClient{
		rc: rc,
		v3: useV3,
	}
}

// ipamConfigClient implements the api.Client interface for IPAMConfig objects. It
// handles the translation between v1 objects understood by the IPAM codebase in lib/ipam,
// and the CRDs which are used to actually store the data in the Kubernetes API.
// It uses a customK8sResourceClient under the covers to perform CRUD operations on
// kubernetes CRDs.
type ipamConfigClient struct {
	rc customResourceClient
	v3 bool
}

// toV1 converts the given v3 CRD KVPair into a v1 model representation
// which can be passed to the IPAM code.
func (c ipamConfigClient) toV1(kvpv3 *model.KVPair) (*model.KVPair, error) {
	switch kvpv3.Value.(type) {
	case *libapiv3.IPAMConfiguration:
		v3obj := kvpv3.Value.(*libapiv3.IPAMConfiguration)
		return &model.KVPair{
			Key: model.IPAMConfigKey{},
			Value: &model.IPAMConfig{
				StrictAffinity:     v3obj.Spec.StrictAffinity,
				AutoAllocateBlocks: v3obj.Spec.AutoAllocateBlocks,
				MaxBlocksPerHost:   v3obj.Spec.MaxBlocksPerHost,
			},
			Revision: kvpv3.Revision,
			UID:      &kvpv3.Value.(*libapiv3.IPAMConfiguration).UID,
		}, nil
	case *v3.IPAMConfiguration:
		v3obj := kvpv3.Value.(*v3.IPAMConfiguration)
		return &model.KVPair{
			Key: model.IPAMConfigKey{},
			Value: &model.IPAMConfig{
				StrictAffinity:     v3obj.Spec.StrictAffinity,
				AutoAllocateBlocks: v3obj.Spec.AutoAllocateBlocks,
				MaxBlocksPerHost:   int(v3obj.Spec.MaxBlocksPerHost),
			},
			Revision: kvpv3.Revision,
			UID:      &v3obj.UID,
		}, nil
	}
	return nil, fmt.Errorf("invalid type for IPAMConfig KVPair: %T", kvpv3.Value)
}

// For the first point, toV3 takes the given v1 KVPair and converts it into a v3 representation, suitable
// for writing as a CRD to the Kubernetes API.
func (c ipamConfigClient) toV3(kvpv1 *model.KVPair) *model.KVPair {
	// Build object meta.
	// We only support a singleton resource with name "default".
	m := metav1.ObjectMeta{}
	m.SetName(model.IPAMConfigGlobalName)
	m.SetResourceVersion(kvpv1.Revision)

	apiVersion := "crd.projectcalico.org/v1"
	if c.v3 {
		// If this is a v3 resource, then we need to use the v3 API version.
		apiVersion = "projectcalico.org/v3"
	}

	if c.v3 {
		v1obj := kvpv1.Value.(*model.IPAMConfig)
		return &model.KVPair{
			Key: model.ResourceKey{
				Name: model.IPAMConfigGlobalName,
				Kind: libapiv3.KindIPAMConfig,
			},
			Value: &v3.IPAMConfiguration{
				TypeMeta: metav1.TypeMeta{
					Kind:       libapiv3.KindIPAMConfig,
					APIVersion: apiVersion,
				},
				ObjectMeta: m,
				Spec: v3.IPAMConfigurationSpec{
					StrictAffinity:     v1obj.StrictAffinity,
					AutoAllocateBlocks: v1obj.AutoAllocateBlocks,
					MaxBlocksPerHost:   int32(v1obj.MaxBlocksPerHost),
				},
			},
			Revision: kvpv1.Revision,
		}
	} else {
		v1obj := kvpv1.Value.(*model.IPAMConfig)
		return &model.KVPair{
			Key: model.ResourceKey{
				Name: model.IPAMConfigGlobalName,
				Kind: libapiv3.KindIPAMConfig,
			},
			Value: &libapiv3.IPAMConfiguration{
				TypeMeta: metav1.TypeMeta{
					Kind:       libapiv3.KindIPAMConfig,
					APIVersion: apiVersion,
				},
				ObjectMeta: m,
				Spec: libapiv3.IPAMConfigurationSpec{
					StrictAffinity:     v1obj.StrictAffinity,
					AutoAllocateBlocks: v1obj.AutoAllocateBlocks,
					MaxBlocksPerHost:   v1obj.MaxBlocksPerHost,
				},
			},
			Revision: kvpv1.Revision,
		}
	}
}

// There's two possible kV formats to be passed to backend ipamConfig.
// 1. Libcalico-go IPAM passes a v1 model.IPAMConfig directly. [libcalico-go/lib/ipam/ipam.go]
// 2. Calico-apiserver storage passes a kv with libapiv3.IPAMConfiguration

// isV1Key return if the Key is in v1 format.
func isV1Key(key model.Key) bool {
	switch key.(type) {
	case model.IPAMConfigKey: // used by Calico IPAM [libcalico-go/lib/ipam/ipam.go]
		return true
	case model.ResourceKey: // used by clientv3 resource API [libcalico-go/lib/clientv3/resources.go]
		return false
	default:
		log.Panic("ipamConfigClient : wrong key interface type")
	}
	return false
}

func (c *ipamConfigClient) createV1(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	nkvp, err := c.rc.Create(ctx, c.toV3(kvp))
	if err != nil {
		return nil, err
	}
	kvp, err = c.toV1(nkvp)
	if err != nil {
		return nil, err
	}
	return kvp, nil
}

func (c *ipamConfigClient) createV3(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	return c.rc.Create(ctx, kvp)
}

func (c *ipamConfigClient) Create(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	log.Debug("Received Create request on IPAMConfig type")
	if isV1Key(kvp.Key) {
		// From the IPAM code - we need to convert to CRD format.
		return c.createV1(ctx, kvp)
	}
	// From the v3 client - it's already in CRD format.
	return c.createV3(ctx, kvp)
}

func (c *ipamConfigClient) updateV1(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	nkvp, err := c.rc.Update(ctx, c.toV3(kvp))
	if err != nil {
		return nil, err
	}
	kvp, err = c.toV1(nkvp)
	if err != nil {
		return nil, err
	}
	return kvp, nil
}

func (c *ipamConfigClient) updateV3(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	return c.rc.Update(ctx, kvp)
}

func (c *ipamConfigClient) Update(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	log.Debug("Received Update request on IPAMConfig type")
	if isV1Key(kvp.Key) {
		// From the IPAM code - we need to convert to CRD format.
		return c.updateV1(ctx, kvp)
	}
	// From the v3 client - it's already in CRD format.
	return c.updateV3(ctx, kvp)
}

func (c *ipamConfigClient) DeleteKVP(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	return c.Delete(ctx, kvp.Key, kvp.Revision, kvp.UID)
}

func (c *ipamConfigClient) deleteV1(ctx context.Context, key model.Key, revision string, uid *types.UID) (*model.KVPair, error) {
	k := model.ResourceKey{
		Name: model.IPAMConfigGlobalName,
		Kind: libapiv3.KindIPAMConfig,
	}
	kvp, err := c.rc.Delete(ctx, k, revision, uid)
	if err != nil {
		return nil, err
	}
	v1nkvp, err := c.toV1(kvp)
	if err != nil {
		return nil, err
	}
	return v1nkvp, nil
}

func (c *ipamConfigClient) deleteV3(ctx context.Context, key model.Key, revision string, uid *types.UID) (*model.KVPair, error) {
	return c.rc.Delete(ctx, key, revision, uid)
}

func (c *ipamConfigClient) Delete(ctx context.Context, key model.Key, revision string, uid *types.UID) (*model.KVPair, error) {
	log.Debug("Received Delete request on IPAMConfig type")
	if isV1Key(key) {
		// From the IPAM code - we need to convert to CRD format.
		return c.deleteV1(ctx, key, revision, uid)
	}
	// From the v3 client - it's already in CRD format.
	return c.deleteV3(ctx, key, revision, uid)
}

func (c *ipamConfigClient) getV1(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	k := model.ResourceKey{
		Name: model.IPAMConfigGlobalName,
		Kind: libapiv3.KindIPAMConfig,
	}
	kvp, err := c.rc.Get(ctx, k, revision)
	if err != nil {
		return nil, err
	}
	v1kvp, err := c.toV1(kvp)
	if err != nil {
		return nil, err
	}
	return v1kvp, nil
}

func (c *ipamConfigClient) getV3(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	return c.rc.Get(ctx, key, revision)
}

func (c *ipamConfigClient) Get(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	log.Debug("Received Get request on IPAMConfig type")
	if isV1Key(key) {
		// From the IPAM code - we need to convert to CRD format.
		return c.getV1(ctx, key, revision)
	}
	// From the v3 client - it's already in CRD format.
	return c.getV3(ctx, key, revision)
}

func (c *ipamConfigClient) List(ctx context.Context, list model.ListInterface, revision string) (*model.KVPairList, error) {
	// List can only ever come from the v3 client, by passing a ResourceListOptions.
	log.Debug("Received List request on IPAMConfig type")
	return c.rc.List(ctx, list, revision)
}

func (c *ipamConfigClient) Watch(ctx context.Context, list model.ListInterface, options api.WatchOptions) (api.WatchInterface, error) {
	// List can only ever come from the v3 client, by passing a ResourceListOptions.
	log.Debug("Received Watch request on IPAMConfig type")
	return c.rc.Watch(ctx, list, options)
}

// EnsureInitialized is a no-op since the CRD should be
// initialized in advance.
func (c *ipamConfigClient) EnsureInitialized() error {
	return nil
}
