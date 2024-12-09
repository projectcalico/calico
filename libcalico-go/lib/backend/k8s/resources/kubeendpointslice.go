// Copyright (c) 2017-2021 Tigera, Inc. All rights reserved.

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
	"fmt"

	log "github.com/sirupsen/logrus"
	discovery "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
)

// NewKubernetesEndpointSliceClient returns a new client for interacting with Kubernetes EndpointSlice objects.
// Note that this client is only intended for use by the felix syncer in KDD mode, and as such is largely unimplemented
// except for the functions required by the syncer.
func NewKubernetesEndpointSliceClient(c *kubernetes.Clientset) K8sResourceClient {
	return &endpointSliceClient{
		Converter: conversion.NewConverter(),
		clientSet: c,
	}
}

// Implements the api.Client interface for Kubernetes EndpointSlice.
type endpointSliceClient struct {
	conversion.Converter
	clientSet *kubernetes.Clientset
}

func (c *endpointSliceClient) Create(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	log.Debug("Received Create request on EndpointSlice type")
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: kvp.Key,
		Operation:  "Create",
	}
}

func (c *endpointSliceClient) Update(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	log.Debug("Received Update request on EndpointSlice type")
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: kvp.Key,
		Operation:  "Update",
	}
}

func (c *endpointSliceClient) Apply(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: kvp.Key,
		Operation:  "Apply",
	}
}

func (c *endpointSliceClient) DeleteKVP(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	return c.Delete(ctx, kvp.Key, kvp.Revision, kvp.UID)
}

func (c *endpointSliceClient) Delete(ctx context.Context, key model.Key, revision string, uid *types.UID) (*model.KVPair, error) {
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: key,
		Operation:  "Delete",
	}
}

func (c *endpointSliceClient) Get(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: key,
		Operation:  "Get",
	}
}

func (c *endpointSliceClient) List(ctx context.Context, list model.ListInterface, revision string) (*model.KVPairList, error) {
	listFunc := func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
		return c.clientSet.DiscoveryV1().EndpointSlices("").List(ctx, opts)
	}
	convertFunc := func(r Resource) ([]*model.KVPair, error) {
		kvp, err := c.EndpointSliceToKVP(r.(*discovery.EndpointSlice))
		if err != nil {
			return nil, err
		}
		return []*model.KVPair{kvp}, nil
	}

	// For each object returned from the API server, add it to a KVPairList.
	logContext := log.WithField("Resource", "EndpointSlice")
	return pagedList(ctx, logContext, revision, list, convertFunc, listFunc)
}

func (c *endpointSliceClient) Watch(ctx context.Context, list model.ListInterface, options api.WatchOptions) (api.WatchInterface, error) {
	_, ok := list.(model.ResourceListOptions)
	if !ok {
		return nil, fmt.Errorf("ListInterface is not a ResourceListOptions: %s", list)
	}

	log.Debugf("Watching Kubernetes EndpointSlice at revision %q", options.Revision)
	k8sOpts := watchOptionsToK8sListOptions(options)
	k8sRawWatch, err := c.clientSet.DiscoveryV1().EndpointSlices("").Watch(ctx, k8sOpts)
	if err != nil {
		return nil, K8sErrorToCalico(err, list)
	}
	converter := func(r Resource) (*model.KVPair, error) {
		es, ok := r.(*discovery.EndpointSlice)
		if !ok {
			return nil, errors.New("KubernetesEndpointSlice conversion with incorrect k8s resource type")
		}

		return c.EndpointSliceToKVP(es)
	}
	return newK8sWatcherConverter(ctx, "KubernetesEndpointSlice", converter, k8sRawWatch), nil
}

func (c *endpointSliceClient) EnsureInitialized() error {
	return nil
}
