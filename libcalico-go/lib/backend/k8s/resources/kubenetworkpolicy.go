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

	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/libcalico-go/lib/errors"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

// NewKubernetesNetworkPolicyClient returns a new client for interacting with Kubernetes NetworkPolicy objects.
// Note that this client is only intended for use by the felix syncer in KDD mode, and as such is largely unimplemented
// except for the functions required by the syncer.
func NewKubernetesNetworkPolicyClient(c *kubernetes.Clientset) K8sResourceClient {
	return &networkPolicyClient{
		Converter: conversion.NewConverter(),
		clientSet: c,
	}
}

// Implements the api.Client interface for Kubernetes NetworkPolicy.
type networkPolicyClient struct {
	conversion.Converter
	clientSet *kubernetes.Clientset
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
	log.Debug("Received List request on Kubernetes NetworkPolicy type")
	// List all of the k8s NetworkPolicy objects.
	networkPolicies := networkingv1.NetworkPolicyList{}
	req := c.clientSet.NetworkingV1().RESTClient().
		Get().
		Resource("networkpolicies")
	err := req.Do(ctx).Into(&networkPolicies)
	if err != nil {
		log.WithError(err).Info("Unable to list K8s Network Policy resources")
		return nil, K8sErrorToCalico(err, list)
	}

	// For each policy, turn it into a Policy and generate the list.
	npKvps := model.KVPairList{KVPairs: []*model.KVPair{}}
	for _, p := range networkPolicies.Items {
		kvp, err := c.K8sNetworkPolicyToCalico(&p)
		if err != nil {
			log.WithError(err).Info("Failed to convert K8s Network Policy")
			return nil, err
		}
		npKvps.KVPairs = append(npKvps.KVPairs, kvp)
	}

	// Add in the Revision information.
	npKvps.Revision = networkPolicies.ResourceVersion
	log.WithFields(log.Fields{
		"num_kvps": len(npKvps.KVPairs),
		"revision": npKvps.Revision}).Debug("Returning Kubernetes NP KVPs")
	return &npKvps, nil
}

func (c *networkPolicyClient) Watch(ctx context.Context, list model.ListInterface, revision string) (api.WatchInterface, error) {
	// Build watch options to pass to k8s.
	opts := metav1.ListOptions{Watch: true}
	_, ok := list.(model.ResourceListOptions)
	if !ok {
		return nil, fmt.Errorf("ListInterface is not a ResourceListOptions: %s", list)
	}

	opts.ResourceVersion = revision
	log.Debugf("Watching Kubernetes NetworkPolicy at revision %q", revision)
	k8sRawWatch, err := c.clientSet.NetworkingV1().NetworkPolicies("").Watch(ctx, opts)
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
