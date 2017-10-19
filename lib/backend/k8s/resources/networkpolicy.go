// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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
	"reflect"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	apiv2 "github.com/projectcalico/libcalico-go/lib/apis/v2"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/libcalico-go/lib/errors"

	extensions "k8s.io/api/extensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

const (
	NetworkPolicyResourceName = "NetworkPolicies"
	NetworkPolicyCRDName      = "networkpolicies.crd.projectcalico.org"
)

func NewNetworkPolicyClient(c *kubernetes.Clientset, r *rest.RESTClient) K8sResourceClient {
	crdClient := &customK8sResourceClient{
		restClient:      r,
		name:            NetworkPolicyCRDName,
		resource:        NetworkPolicyResourceName,
		description:     "Calico Network Policies",
		k8sResourceType: reflect.TypeOf(apiv2.NetworkPolicy{}),
		k8sListType:     reflect.TypeOf(apiv2.NetworkPolicyList{}),
		namespaced:      true,
	}
	return &networkPolicyClient{
		clientSet: c,
		crdClient: crdClient,
		converter: conversion.Converter{},
	}
}

// Implements the api.Client interface for NetworkPolicys.
type networkPolicyClient struct {
	clientSet *kubernetes.Clientset
	crdClient *customK8sResourceClient
	converter conversion.Converter
}

func (c *networkPolicyClient) Create(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	log.Debug("Received Create request on NetworkPolicy type")
	key := kvp.Key.(model.ResourceKey)
	if strings.HasPrefix(key.Name, "knp.default.") {
		// We don't support Create of a Kubernetes NetworkPolicy.
		return nil, cerrors.ErrorOperationNotSupported{
			Identifier: kvp.Key,
			Operation:  "Create",
		}
	}
	return c.crdClient.Create(ctx, kvp)
}

func (c *networkPolicyClient) Update(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	log.Debug("Received Update request on NetworkPolicy type")
	key := kvp.Key.(model.ResourceKey)
	if strings.HasPrefix(key.Name, "knp.default.") {
		// We don't support Update of a Kubernetes NetworkPolicy.
		return nil, cerrors.ErrorOperationNotSupported{
			Identifier: kvp.Key,
			Operation:  "Update",
		}
	}
	return c.crdClient.Update(ctx, kvp)
}

func (c *networkPolicyClient) Apply(kvp *model.KVPair) (*model.KVPair, error) {
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: kvp.Key,
		Operation:  "Apply",
	}
}

func (c *networkPolicyClient) Delete(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	log.Debug("Received Delete request on NetworkPolicy type")
	k := key.(model.ResourceKey)
	if strings.HasPrefix(k.Name, "knp.default.") {
		// We don't support Delete of a Kubernetes NetworkPolicy.
		return nil, cerrors.ErrorOperationNotSupported{
			Identifier: key,
			Operation:  "Delete",
		}
	}
	return c.crdClient.Delete(ctx, key, revision)
}

func (c *networkPolicyClient) Get(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	log.Debug("Received Get request on NetworkPolicy type")
	k := key.(model.ResourceKey)
	if k.Name == "" {
		return nil, errors.New("Missing policy name")
	}

	// Check to see if this is backed by a NetworkPolicy.
	if strings.HasPrefix(k.Name, "knp.default.") {
		// Backed by a NetworkPolicy. Parse out the namespace / name.
		namespace, policyName, err := c.converter.ParsePolicyNameNetworkPolicy(k.Name)
		if err != nil {
			return nil, cerrors.ErrorResourceDoesNotExist{Err: err, Identifier: k}
		}

		// Get the NetworkPolicy from the API and convert it.
		networkPolicy := extensions.NetworkPolicy{}
		err = c.clientSet.Extensions().RESTClient().
			Get().
			Resource("networkpolicies").
			Namespace(namespace).
			Name(policyName).
			Timeout(10 * time.Second).
			Do().Into(&networkPolicy)
		if err != nil {
			return nil, K8sErrorToCalico(err, k)
		}
		return c.converter.K8sNetworkPolicyToCalico(&networkPolicy)
	} else {
		return c.crdClient.Get(ctx, k, revision)
	}
}

func (c *networkPolicyClient) List(ctx context.Context, list model.ListInterface, revision string) (*model.KVPairList, error) {
	log.Debug("Received List request on NetworkPolicy type")
	l := list.(model.ResourceListOptions)
	if l.Name != "" {
		// Exact lookup on a NetworkPolicy.
		kvp, err := c.Get(ctx, model.ResourceKey{Name: l.Name, Namespace: l.Namespace, Kind: l.Kind}, revision)
		if err != nil {
			// Return empty slice of KVPair if the object doesn't exist, return the error otherwise.
			if _, ok := err.(cerrors.ErrorResourceDoesNotExist); ok {
				return &model.KVPairList{
					KVPairs:  []*model.KVPair{},
					Revision: revision,
				}, nil
			} else {
				return nil, err
			}
		}

		return &model.KVPairList{
			KVPairs:  []*model.KVPair{kvp},
			Revision: revision,
		}, nil
	}

	// Otherwise, list all NetworkPolicy objects in all Namespaces.
	networkPolicies := extensions.NetworkPolicyList{}
	err := c.clientSet.Extensions().RESTClient().
		Get().
		Resource("networkpolicies").
		Timeout(10 * time.Second).
		Do().Into(&networkPolicies)
	if err != nil {
		return nil, K8sErrorToCalico(err, l)
	}

	// For each policy, turn it into a Policy and generate the list.
	ret := []*model.KVPair{}
	for _, p := range networkPolicies.Items {
		kvp, err := c.converter.K8sNetworkPolicyToCalico(&p)
		if err != nil {
			return nil, err
		}
		ret = append(ret, kvp)
	}

	// List all Namespaced Calico Network Policies.
	nps, err := c.crdClient.List(ctx, l, revision)
	if err != nil {
		return nil, err
	}
	ret = append(ret, nps.KVPairs...)

	return &model.KVPairList{
		KVPairs:  ret,
		Revision: revision,
	}, nil
}

func (c *networkPolicyClient) EnsureInitialized() error {
	return nil
}

func (c *networkPolicyClient) Watch(ctx context.Context, list model.ListInterface, revision string) (api.WatchInterface, error) {
	// TODO(doublek): We are only watching k8s backed NetworkPolicy. Will need to add
	// the ability to watch both CRD and k8s NetworkPolicy.
	resl := list.(model.ResourceListOptions)
	if len(resl.Name) != 0 {
		return nil, fmt.Errorf("cannot watch specific resource instance: %s", list.(model.ResourceListOptions).Name)
	}

	k8sWatchClient := cache.NewListWatchFromClient(
		c.clientSet.ExtensionsV1beta1().RESTClient(),
		"networkpolicies",
		resl.Namespace,
		fields.Everything())
	k8sWatch, err := k8sWatchClient.WatchFunc(metav1.ListOptions{ResourceVersion: revision})
	if err != nil {
		return nil, K8sErrorToCalico(err, list)
	}
	converter := func(r Resource) (*model.KVPair, error) {
		np, ok := r.(*extensions.NetworkPolicy)
		if !ok {
			return nil, errors.New("NetworkPolicy conversion with incorrect k8s resource type")
		}
		return c.converter.K8sNetworkPolicyToCalico(np)
	}
	return newK8sWatcherConverter(ctx, converter, k8sWatch), nil
	// return c.crdClient.Watch(ctx, list, revision)
}
