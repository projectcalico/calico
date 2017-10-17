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
	"errors"
	"fmt"

	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	kapiv1 "k8s.io/api/core/v1"

	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/libcalico-go/lib/errors"
)

func NewProfileClient(c *kubernetes.Clientset) K8sResourceClient {
	return &profileClient{
		clientSet: c,
	}
}

// Implements the api.Client interface for Profiles.
type profileClient struct {
	clientSet *kubernetes.Clientset
	converter conversion.Converter
}

func (c *profileClient) Create(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	log.Warn("Operation Create is not supported on Profile type")
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: kvp.Key,
		Operation:  "Create",
	}
}

func (c *profileClient) Update(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	log.Warn("Operation Update is not supported on Profile type")
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: kvp.Key,
		Operation:  "Update",
	}
}

func (c *profileClient) Delete(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	log.Warn("Operation Delete is not supported on Profile type")
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: key,
		Operation:  "Delete",
	}
}

func (c *profileClient) Get(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	log.Debug("Received Get request on Profile type")
	rk := key.(model.ResourceKey)
	if rk.Name == "" {
		return nil, fmt.Errorf("Profile key missing name: %+v", rk)
	}
	namespaceName, err := c.converter.ProfileNameToNamespace(rk.Name)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse Profile name: %s", err)
	}
	namespace, err := c.clientSet.CoreV1().Namespaces().Get(namespaceName, metav1.GetOptions{})
	if err != nil {
		return nil, K8sErrorToCalico(err, rk)
	}

	return c.converter.NamespaceToProfile(namespace)
}

func (c *profileClient) List(ctx context.Context, list model.ListInterface, revision string) (*model.KVPairList, error) {
	log.Debug("Received List request on Profile type")
	nl := list.(model.ResourceListOptions)
	kvps := []*model.KVPair{}

	// If a name is specified, then do an exact lookup.
	if nl.Name != "" {
		kvp, err := c.Get(ctx, model.ResourceKey{Name: nl.Name, Kind: nl.Kind}, revision)
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
			KVPairs:  []*model.KVPair{kvp},
			Revision: revision,
		}, nil
	}

	// Otherwise, enumerate all.
	namespaces, err := c.clientSet.CoreV1().Namespaces().List(metav1.ListOptions{})
	if err != nil {
		return nil, K8sErrorToCalico(err, nl)
	}

	// For each Namespace, return a profile.
	for _, ns := range namespaces.Items {
		kvp, err := c.converter.NamespaceToProfile(&ns)
		if err != nil {
			log.Errorf("Unable to convert k8s Namespace to Calico Profile: Namespace=%s: %v", ns.Name, err)
			continue
		}
		kvps = append(kvps, kvp)
	}
	return &model.KVPairList{
		KVPairs:  kvps,
		Revision: namespaces.ResourceVersion,
	}, nil
}

func (c *profileClient) EnsureInitialized() error {
	return nil
}

func (c *profileClient) Watch(ctx context.Context, list model.ListInterface, revision string) (api.WatchInterface, error) {
	if len(list.(model.ResourceListOptions).Name) != 0 {
		return nil, fmt.Errorf("cannot watch specific resource instance: %s", list.(model.ResourceListOptions).Name)
	}

	k8sWatch, err := c.clientSet.CoreV1().Namespaces().Watch(metav1.ListOptions{ResourceVersion: revision})
	if err != nil {
		return nil, K8sErrorToCalico(err, list)
	}
	converter := func(r Resource) (*model.KVPair, error) {
		k8sNamespace, ok := r.(*kapiv1.Namespace)
		if !ok {
			return nil, errors.New("profile conversion with incorrect k8s resource type")
		}
		return c.converter.NamespaceToProfile(k8sNamespace)
	}
	return newK8sWatcherConverter(ctx, converter, k8sWatch), nil
}
