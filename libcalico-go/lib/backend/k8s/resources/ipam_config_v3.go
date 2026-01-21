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
	IPAMConfigResourceNameV3 = "IPAMConfigurations"
)

// NewIPAMConfigClientV3 returns a new client for managing IPAMConfig resources, as used by the
// libcalico-go/lib/clientv3 code.
func NewIPAMConfigClientV3(r rest.Interface, v3CRDs bool) K8sResourceClient {
	return &v3IPAMConfigClient{
		rc: ipamConfigResourceClient(r, v3CRDs),
		v3: v3CRDs,
	}
}

type v3IPAMConfigClient struct {
	rc customResourceClient
	v3 bool
}

func (c v3IPAMConfigClient) getBackingTypeMeta() metav1.TypeMeta {
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

func (c *v3IPAMConfigClient) Create(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	log.Debug("Received Create request on IPAMConfig type")

	// Ensure the correct type meta is set based on the backing CRD version.
	kvp.Value.(*v3.IPAMConfiguration).TypeMeta = c.getBackingTypeMeta()

	return c.rc.Create(ctx, kvp)
}

func (c *v3IPAMConfigClient) Update(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	log.Debug("Received Update request on IPAMConfig type")

	// Ensure the correct type meta is set based on the backing CRD version.
	kvp.Value.(*v3.IPAMConfiguration).TypeMeta = c.getBackingTypeMeta()

	return c.rc.Update(ctx, kvp)
}

func (c *v3IPAMConfigClient) DeleteKVP(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	return c.Delete(ctx, kvp.Key, kvp.Revision, kvp.UID)
}

func (c *v3IPAMConfigClient) Delete(ctx context.Context, key model.Key, revision string, uid *types.UID) (*model.KVPair, error) {
	log.Debug("Received Delete request on IPAMConfig type")
	return c.rc.Delete(ctx, key, revision, uid)
}

func (c *v3IPAMConfigClient) Get(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	log.Debug("Received Get request on IPAMConfig type")
	return c.rc.Get(ctx, key, revision)
}

func (c *v3IPAMConfigClient) List(ctx context.Context, list model.ListInterface, revision string) (*model.KVPairList, error) {
	// List can only ever come from the v3 client, by passing a ResourceListOptions.
	log.Debug("Received List request on IPAMConfig type")
	return c.rc.List(ctx, list, revision)
}

func (c *v3IPAMConfigClient) Watch(ctx context.Context, list model.ListInterface, options api.WatchOptions) (api.WatchInterface, error) {
	// List can only ever come from the v3 client, by passing a ResourceListOptions.
	log.Debug("Received Watch request on IPAMConfig type")
	return c.rc.Watch(ctx, list, options)
}

// EnsureInitialized is a no-op since the CRD should be
// initialized in advance.
func (c *v3IPAMConfigClient) EnsureInitialized() error {
	return nil
}
