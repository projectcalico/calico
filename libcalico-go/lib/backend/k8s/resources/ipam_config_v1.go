// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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
	IPAMConfigResourceName = "IPAMConfigs"
)

// NewIPAMConfigClientOld returns a new client for managing IPAMConfig resources, as used by the
// libcalico-go/lib/ipam code.
func NewIPAMConfigClientV1(r rest.Interface, group BackingAPIGroup) K8sResourceClient {
	return &v1IPAMConfigClient{
		rc: ipamConfigResourceClient(r, group),
		v3: group == BackingAPIGroupV3,
	}
}

type v1IPAMConfigClient struct {
	rc customResourceClient
	v3 bool
}

// crdToV1 converts the given CRD KVPair into a v1 model representation which can be passed back to the IPAM code.
func (c v1IPAMConfigClient) crdToV1(kvp *model.KVPair) (*model.KVPair, error) {
	switch kvp.Value.(type) {
	case *libapiv3.IPAMConfig:
		v3obj := kvp.Value.(*libapiv3.IPAMConfig)
		return &model.KVPair{
			Key: model.IPAMConfigKey{},
			Value: &model.IPAMConfig{
				StrictAffinity:     v3obj.Spec.StrictAffinity,
				AutoAllocateBlocks: v3obj.Spec.AutoAllocateBlocks,
				MaxBlocksPerHost:   v3obj.Spec.MaxBlocksPerHost,
			},
			Revision: kvp.Revision,
			UID:      &kvp.Value.(*libapiv3.IPAMConfig).UID,
		}, nil
	case *v3.IPAMConfiguration:
		v3obj := kvp.Value.(*v3.IPAMConfiguration)
		return &model.KVPair{
			Key: model.IPAMConfigKey{},
			Value: &model.IPAMConfig{
				StrictAffinity:     v3obj.Spec.StrictAffinity,
				AutoAllocateBlocks: v3obj.Spec.AutoAllocateBlocks,
				MaxBlocksPerHost:   int(v3obj.Spec.MaxBlocksPerHost),
			},
			Revision: kvp.Revision,
			UID:      &v3obj.UID,
		}, nil
	}
	return nil, fmt.Errorf("invalid type for IPAM configuration KVPair: %T", kvp.Value)
}

func (c v1IPAMConfigClient) getBackingTypeMeta() metav1.TypeMeta {
	if c.v3 {
		// If this is a v3 resource, then we need to use the v3 API version.
		return metav1.TypeMeta{
			Kind:       v3.KindIPAMConfiguration,
			APIVersion: "projectcalico.org/v3",
		}
	}
	return metav1.TypeMeta{
		Kind:       libapiv3.KindIPAMConfig,
		APIVersion: "crd.projectcalico.org/v1",
	}
}

// toCRD converts the given v1 KVPair into a CRD KVPair which can be stored
// in the Kubernetes API.
func (c v1IPAMConfigClient) toCRD(kvpv1 *model.KVPair) *model.KVPair {
	// Build object meta.
	// We only support a singleton resource with name "default".
	m := metav1.ObjectMeta{}
	m.SetName(model.IPAMConfigGlobalName)
	m.SetResourceVersion(kvpv1.Revision)

	typeMeta := c.getBackingTypeMeta()

	if c.v3 {
		v1obj := kvpv1.Value.(*model.IPAMConfig)
		return &model.KVPair{
			Key: model.ResourceKey{
				Name: model.IPAMConfigGlobalName,
				Kind: v3.KindIPAMConfiguration,
			},
			Value: &v3.IPAMConfiguration{
				TypeMeta:   typeMeta,
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
			Value: &libapiv3.IPAMConfig{
				TypeMeta:   typeMeta,
				ObjectMeta: m,
				Spec: libapiv3.IPAMConfigSpec{
					StrictAffinity:     v1obj.StrictAffinity,
					AutoAllocateBlocks: v1obj.AutoAllocateBlocks,
					MaxBlocksPerHost:   v1obj.MaxBlocksPerHost,
				},
			},
			Revision: kvpv1.Revision,
		}
	}
}

func (c *v1IPAMConfigClient) Create(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	log.Debug("Received Create request on IPAMConfig type")
	nkvp, err := c.rc.Create(ctx, c.toCRD(kvp))
	if err != nil {
		return nil, err
	}
	kvp, err = c.crdToV1(nkvp)
	if err != nil {
		return nil, err
	}
	return kvp, nil
}

func (c *v1IPAMConfigClient) Update(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	log.Debug("Received Update request on IPAMConfig type")
	nkvp, err := c.rc.Update(ctx, c.toCRD(kvp))
	if err != nil {
		return nil, err
	}
	kvp, err = c.crdToV1(nkvp)
	if err != nil {
		return nil, err
	}
	return kvp, nil
}

func (c *v1IPAMConfigClient) DeleteKVP(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	return c.Delete(ctx, kvp.Key, kvp.Revision, kvp.UID)
}

func (c *v1IPAMConfigClient) Delete(ctx context.Context, key model.Key, revision string, uid *types.UID) (*model.KVPair, error) {
	log.Debug("Received Delete request on IPAMConfig type")
	k := model.ResourceKey{
		Name: model.IPAMConfigGlobalName,
		Kind: libapiv3.KindIPAMConfig,
	}
	if c.v3 {
		k.Kind = v3.KindIPAMConfiguration
	}
	kvp, err := c.rc.Delete(ctx, k, revision, uid)
	if err != nil {
		return nil, err
	}
	v1nkvp, err := c.crdToV1(kvp)
	if err != nil {
		return nil, err
	}
	return v1nkvp, nil
}

func (c *v1IPAMConfigClient) Get(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	log.Debug("Received Get request on IPAMConfig type")
	k := model.ResourceKey{
		Name: model.IPAMConfigGlobalName,
		Kind: libapiv3.KindIPAMConfig,
	}
	if c.v3 {
		k.Kind = v3.KindIPAMConfiguration
	}
	kvp, err := c.rc.Get(ctx, k, revision)
	if err != nil {
		return nil, err
	}
	v1kvp, err := c.crdToV1(kvp)
	if err != nil {
		return nil, err
	}
	return v1kvp, nil
}

func (c *v1IPAMConfigClient) List(ctx context.Context, list model.ListInterface, revision string) (*model.KVPairList, error) {
	// List s not supported for IPAMConfig resource from the lib/ipam code.
	return nil, fmt.Errorf("List is not supported for IPAMConfig resource")
}

func (c *v1IPAMConfigClient) Watch(ctx context.Context, list model.ListInterface, options api.WatchOptions) (api.WatchInterface, error) {
	// Watch is not supported for IPAMConfig resource from the lib/ipam code.
	return nil, fmt.Errorf("Watch is not supported for IPAMConfig resource")
}

func (c *v1IPAMConfigClient) EnsureInitialized() error {
	return nil
}
