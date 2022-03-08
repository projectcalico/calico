// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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

	log "github.com/sirupsen/logrus"
	kapiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
)

// This client is a direct mapping through to the kubernetes service API. It is used by the k8s-resource wrapper
// client (instantiated using k8s.NewK8sResourceWrapperClient) and provides read-only access to the kubernetes
// resources. This allows a syncer to return the kubernetes resources that are included in this client,
// These resource types are only accessible through the backend client API.

func NewServiceClient(c *kubernetes.Clientset) K8sResourceClient {
	return &serviceClient{
		Converter: conversion.NewConverter(),
		clientSet: c,
	}
}

// Implements the api.Client interface for Kubernetes Service.
type serviceClient struct {
	conversion.Converter
	clientSet *kubernetes.Clientset
}

// Create is not supported.
func (c *serviceClient) Create(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	log.Warn("Operation Create is not supported on Kubernetes Service type")
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: kvp.Key,
		Operation:  "Create",
	}
}

// Update is not supported.
func (c *serviceClient) Update(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	log.Warn("Operation Update is not supported on Kubernetes Service type")
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: kvp.Key,
		Operation:  "Update",
	}
}

func (c *serviceClient) DeleteKVP(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	return c.Delete(ctx, kvp.Key, kvp.Revision, kvp.UID)
}

// Delete is not supported.
func (c *serviceClient) Delete(ctx context.Context, key model.Key, revision string, _ *types.UID) (*model.KVPair, error) {
	log.Warn("Operation Delete is not supported on Kubernetes Service type")
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: key,
		Operation:  "Delete",
	}
}

func (c *serviceClient) Get(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	rk := key.(model.ResourceKey)
	service, err := c.clientSet.CoreV1().Services(rk.Namespace).Get(ctx, rk.Name, metav1.GetOptions{ResourceVersion: revision})
	if err != nil {
		return nil, K8sErrorToCalico(err, key)
	}
	return c.ServiceToKVP(service)
}

func (c *serviceClient) List(ctx context.Context, list model.ListInterface, revision string) (*model.KVPairList, error) {
	log.Debug("Received List request on Kubernetes Service type")
	rl := list.(model.ResourceListOptions)
	kvps := []*model.KVPair{}

	if rl.Name != "" {
		// The service is already fully qualified, so perform a Get instead.
		// If the entry does not exist then we just return an empty list.
		kvp, err := c.Get(ctx, model.ResourceKey{Name: rl.Name, Namespace: rl.Namespace, Kind: model.KindK8sService}, revision)
		if err != nil {
			if _, ok := err.(cerrors.ErrorResourceDoesNotExist); !ok {
				return nil, err
			}
			return &model.KVPairList{
				KVPairs:  kvps,
				Revision: revision,
			}, nil
		}

		kvps = append(kvps, kvp)
		return &model.KVPairList{
			KVPairs:  kvps,
			Revision: revision,
		}, nil
	}

	// Listing all services.
	serviceList, err := c.clientSet.CoreV1().Services(rl.Namespace).List(ctx, metav1.ListOptions{ResourceVersion: revision})
	if err != nil {
		return nil, K8sErrorToCalico(err, list)
	}

	converter := func(r Resource) *model.KVPair {
		kvp, err := c.ServiceToKVP(r.(*kapiv1.Service))
		if err != nil {
			return nil
		}
		return kvp
	}

	for i := range serviceList.Items {
		kvps = append(kvps, converter(&serviceList.Items[i]))
	}

	return &model.KVPairList{
		KVPairs:  kvps,
		Revision: serviceList.ResourceVersion,
	}, nil
}

func (c *serviceClient) EnsureInitialized() error {
	return nil
}

func (c *serviceClient) Watch(ctx context.Context, list model.ListInterface, revision string) (api.WatchInterface, error) {
	// Build watch options to pass to k8s.
	opts := metav1.ListOptions{ResourceVersion: revision, Watch: true}
	rl, ok := list.(model.ResourceListOptions)
	if !ok {
		return nil, fmt.Errorf("ListInterface is not a ResourceListOptions: %s", list)
	}
	if len(rl.Name) != 0 {
		// We've been asked to watch a specific service resource.
		log.WithField("name", rl.Name).Debug("Watching a single service")
		opts.FieldSelector = fields.OneTermEqualSelector("metadata.name", rl.Name).String()
	}

	k8sWatch, err := c.clientSet.CoreV1().Services(rl.Namespace).Watch(ctx, opts)
	if err != nil {
		return nil, K8sErrorToCalico(err, list)
	}
	converter := func(r Resource) (*model.KVPair, error) {
		return c.ServiceToKVP(r.(*kapiv1.Service))
	}
	return newK8sWatcherConverter(ctx, "Kubernetes Service", converter, k8sWatch), nil
}
