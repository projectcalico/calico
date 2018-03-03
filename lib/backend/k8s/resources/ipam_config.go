// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.

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

	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/libcalico-go/lib/errors"
	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	IPAMConfigResourceName = "BlockAffinities"
	IPAMConfigCRDName      = "blockaffinities.crd.projectcalico.org"
)

func NewIPAMConfigClient(c *kubernetes.Clientset, r *rest.RESTClient) K8sResourceClient {
	return &ipamConfigClient{}
}

// Implements the api.Client interface for AffinityBlocks.
type ipamConfigClient struct {
	rc customK8sResourceClient
}

func (c *ipamConfigClient) Create(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	log.Warn("Operation Create is not supported on AffinityBlock type")
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: kvp.Key,
		Operation:  "Create",
	}
}

func (c *ipamConfigClient) Update(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	log.Warn("Operation Update is not supported on AffinityBlock type")
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: kvp.Key,
		Operation:  "Create",
	}
}

func (c *ipamConfigClient) Delete(ctx context.Context, key model.Key, revision string, uid *types.UID) (*model.KVPair, error) {
	log.Warn("Operation Delete is not supported on AffinityBlock type")
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: key,
		Operation:  "Delete",
	}
}

func (c *ipamConfigClient) Get(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	return &model.KVPair{
		Key: model.IPAMConfigKey{},
		Value: &model.IPAMConfig{
			StrictAffinity:     false,
			AutoAllocateBlocks: true,
		},
	}, nil
}

func (c *ipamConfigClient) List(ctx context.Context, list model.ListInterface, revision string) (*model.KVPairList, error) {
	log.Warn("Operation List is not supported on AffinityBlock type")
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: list,
		Operation:  "List",
	}
}

func (c *ipamConfigClient) Watch(ctx context.Context, list model.ListInterface, revision string) (api.WatchInterface, error) {
	log.Warn("Operation Watch is not supported on AffinityBlock type")
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: list,
		Operation:  "Watch",
	}
}

// EnsureInitialized is a no-op since the CRD should be
// initialized in advance.
func (c *ipamConfigClient) EnsureInitialized() error {
	return nil
}
