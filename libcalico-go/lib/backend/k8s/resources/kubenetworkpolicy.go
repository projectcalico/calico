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
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
)

// NewKubernetesNetworkPolicyClient returns a new client for interacting with Kubernetes NetworkPolicy objects.
// Note that this client is only intended for use by the felix syncer in KDD mode, and as such is largely unimplemented
// except for the functions required by the syncer.
func NewKubernetesNetworkPolicyClient(c kubernetes.Interface) K8sResourceClient {
	return &networkPolicyClient{
		Converter: conversion.NewConverter(),
		clientSet: c,
	}
}

// Implements the api.Client interface for Kubernetes NetworkPolicy.
type networkPolicyClient struct {
	conversion.Converter
	clientSet kubernetes.Interface
}

func (c *networkPolicyClient) Create(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	log.Debug("Received Create request on NetworkPolicy type")
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: kvp.Key,
		Operation:  "Create",
	}
}

func (c *networkPolicyClient) Update(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	log.Debug("Received Update request on NetworkPolicy type")
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: kvp.Key,
		Operation:  "Update",
	}
}

func (c *networkPolicyClient) Apply(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: kvp.Key,
		Operation:  "Apply",
	}
}

func (c *networkPolicyClient) DeleteKVP(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	return c.Delete(ctx, kvp.Key, kvp.Revision, kvp.UID)
}

func (c *networkPolicyClient) Delete(ctx context.Context, key model.Key, revision string, uid *types.UID) (*model.KVPair, error) {
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: key,
		Operation:  "Delete",
	}
}

func (c *networkPolicyClient) Get(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: key,
		Operation:  "Get",
	}
}

func (c *networkPolicyClient) List(ctx context.Context, list model.ListInterface, revision string) (*model.KVPairList, error) {
	logContext := log.WithField("Resource", "KubeNetworkPolicy")
	logContext.Debug("Received List request")

	listFunc := func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
		return c.clientSet.NetworkingV1().NetworkPolicies("").List(ctx, opts)
	}
	convertFunc := func(r Resource) ([]*model.KVPair, error) {
		p := r.(*networkingv1.NetworkPolicy)
		kvp, err := c.K8sNetworkPolicyToCalico(p)
		// Silently ignore rule conversion errors. We don't expect any conversion errors
		// since the data given to us here is validated by the Kubernetes API. The conversion
		// code ignores any rules that it cannot parse, and we will pass the valid ones to Felix.
		var e *cerrors.ErrorPolicyConversion
		if err != nil && !errors.As(err, &e) {
			return nil, err
		}
		return []*model.KVPair{kvp}, nil
	}
	return pagedList(ctx, logContext, revision, list, convertFunc, listFunc)
}

func (c *networkPolicyClient) Watch(ctx context.Context, list model.ListInterface, options api.WatchOptions) (api.WatchInterface, error) {

	_, ok := list.(model.ResourceListOptions)
	if !ok {
		return nil, fmt.Errorf("ListInterface is not a ResourceListOptions: %s", list)
	}

	k8sOpts := watchOptionsToK8sListOptions(options)
	log.Debugf("Watching Kubernetes NetworkPolicy at revision %q", options.Revision)
	k8sRawWatch, err := c.clientSet.NetworkingV1().NetworkPolicies("").Watch(ctx, k8sOpts)
	if err != nil {
		return nil, K8sErrorToCalico(err, list)
	}
	converter := func(r Resource) (*model.KVPair, error) {
		np, ok := r.(*networkingv1.NetworkPolicy)
		if !ok {
			return nil, errors.New("KubernetesNetworkPolicy conversion with incorrect k8s resource type")
		}

		return c.K8sNetworkPolicyToCalico(np)
	}
	return newK8sWatcherConverter(ctx, "KubernetesNetworkPolicy", converter, k8sRawWatch), nil
}

func (c *networkPolicyClient) EnsureInitialized() error {
	return nil
}
