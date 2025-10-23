// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clusternetpol "sigs.k8s.io/network-policy-api/apis/v1alpha2"
	client "sigs.k8s.io/network-policy-api/pkg/client/clientset/versioned/typed/apis/v1alpha2"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
)

// NewKubernetesClusterNetworkPolicyClient returns a new client for interacting with k8s ClusterNetworkPolicy objects.
// Note that this client is only intended for use by the felix syncer in KDD mode,
// and as such is largely unimplemented except for the functions required by the syncer.
func NewKubernetesClusterNetworkPolicyClient(
	client *client.PolicyV1alpha2Client,
) K8sResourceClient {
	return &clusterNetworkPolicyClient{
		Converter: conversion.NewConverter(),
		client:    client,
	}
}

// Implements the api.Client interface for Kubernetes ClusterNetworkPolicy.
type clusterNetworkPolicyClient struct {
	conversion.Converter
	client *client.PolicyV1alpha2Client
}

func (c *clusterNetworkPolicyClient) Create(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	log.Debug("Received Create request on ClusterNetworkPolicy type")
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: kvp.Key,
		Operation:  "Create",
	}
}

func (c *clusterNetworkPolicyClient) Update(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	log.Debug("Received Update request on ClusterNetworkPolicy type")
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: kvp.Key,
		Operation:  "Update",
	}
}

func (c *clusterNetworkPolicyClient) DeleteKVP(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	return c.Delete(ctx, kvp.Key, kvp.Revision, kvp.UID)
}

func (c *clusterNetworkPolicyClient) Delete(ctx context.Context, key model.Key, revision string, uid *types.UID) (*model.KVPair, error) {
	log.Debug("Received Delete request on ClusterNetworkPolicy type")
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: key,
		Operation:  "Delete",
	}
}

func (c *clusterNetworkPolicyClient) Get(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	log.Debug("Received Get request on ClusterNetworkPolicy type")
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: key,
		Operation:  "Get",
	}
}

func (c *clusterNetworkPolicyClient) List(ctx context.Context, list model.ListInterface, revision string) (*model.KVPairList, error) {
	logContext := log.WithField("Resource", "ClusterNetworkPolicy")
	logContext.Debug("Received List request")

	listFunc := func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
		return c.client.ClusterNetworkPolicies().List(ctx, opts)
	}
	convertFunc := func(r Resource) ([]*model.KVPair, error) {
		kcnp := r.(*clusternetpol.ClusterNetworkPolicy)
		kvp, err := c.K8sClusterNetworkPolicyToCalico(kcnp)
		// Silently ignore rule conversion errors. We don't expect any conversion errors
		// since the data given to us here is validated by the Kubernetes API. The conversion
		// code ignores any rules that it cannot parse, and we will pass the valid ones to Felix.
		var e *cerrors.ErrorClusterNetworkPolicyConversion
		if err != nil && !errors.As(err, &e) {
			return nil, err
		}
		return []*model.KVPair{kvp}, nil
	}
	return pagedList(ctx, logContext, revision, list, convertFunc, listFunc)
}

func (c *clusterNetworkPolicyClient) Watch(ctx context.Context, list model.ListInterface, options api.WatchOptions) (api.WatchInterface, error) {
	_, ok := list.(model.ResourceListOptions)
	if !ok {
		return nil, fmt.Errorf("ListInterface is not a ResourceListOptions: %s", list)
	}
	log.Debugf("Watching Kubernetes ClusterNetworkPolicy at revision %q", options.Revision)
	k8sOpts := watchOptionsToK8sListOptions(options)
	k8sRawWatch, err := c.client.ClusterNetworkPolicies().Watch(ctx, k8sOpts)
	if err != nil {
		return nil, K8sErrorToCalico(err, list)
	}
	converter := func(r Resource) (*model.KVPair, error) {
		kcnp, ok := r.(*clusternetpol.ClusterNetworkPolicy)
		if !ok {
			return nil, errors.New("Kubernetes ClusterNetworkPolicy conversion with incorrect k8s resource type")
		}

		return c.K8sClusterNetworkPolicyToCalico(kcnp)
	}
	return newK8sWatcherConverter(ctx, "Kubernetes ClusterNetworkPolicy", converter, k8sRawWatch), nil
}

func (c *clusterNetworkPolicyClient) EnsureInitialized() error {
	return nil
}
