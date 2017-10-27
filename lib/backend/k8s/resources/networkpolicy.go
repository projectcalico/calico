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
	"sync/atomic"

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
	"k8s.io/client-go/kubernetes/scheme"
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
		k8sResourceTypeMeta: metav1.TypeMeta{
			Kind:       apiv2.KindNetworkPolicy,
			APIVersion: apiv2.GroupVersionCurrent,
		},
		k8sListType:  reflect.TypeOf(apiv2.NetworkPolicyList{}),
		resourceKind: apiv2.KindNetworkPolicy,
		namespaced:   true,
	}
	return &networkPolicyClient{
		clientSet: c,
		crdClient: crdClient,
		converter: conversion.Converter{},
	}
}

// Implements the api.Client interface for NetworkPolicys.
type networkPolicyClient struct {
	resourceName string
	clientSet    *kubernetes.Clientset
	crdClient    *customK8sResourceClient
	converter    conversion.Converter
}

func (c *networkPolicyClient) Create(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	log.Debug("Received Create request on NetworkPolicy type")
	key := kvp.Key.(model.ResourceKey)
	if strings.HasPrefix(key.Name, conversion.K8sNetworkPolicyNamePrefix) {
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
	if strings.HasPrefix(key.Name, conversion.K8sNetworkPolicyNamePrefix) {
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
	if strings.HasPrefix(k.Name, conversion.K8sNetworkPolicyNamePrefix) {
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
	if k.Namespace == "" {
		return nil, errors.New("Missing policy namespace")
	}

	// Check to see if this is backed by a NetworkPolicy.
	if strings.HasPrefix(k.Name, conversion.K8sNetworkPolicyNamePrefix) {
		// Backed by a NetworkPolicy - extract the name.
		policyName := strings.TrimPrefix(k.Name, conversion.K8sNetworkPolicyNamePrefix)

		// Get the NetworkPolicy from the API and convert it.
		networkPolicy := extensions.NetworkPolicy{}
		err := c.clientSet.Extensions().RESTClient().
			Get().
			Resource("networkpolicies").
			Namespace(k.Namespace).
			Name(policyName).
			VersionedParams(&metav1.GetOptions{ResourceVersion: revision}, scheme.ParameterCodec).
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

	// List all Namespaced Calico Network Policies.
	npKvps, err := c.crdClient.List(ctx, l, revision)
	if err != nil {
		log.WithError(err).Info("Unable to list Calico CRD-backed Network Policy resources")
		return nil, err
	}

	// List all of the k8s NetworkPolicy objects in all Namespaces.
	networkPolicies := extensions.NetworkPolicyList{}
	req := c.clientSet.Extensions().RESTClient().
		Get().
		Resource("networkpolicies")
	if l.Namespace != "" {
		// Add the namespace if requested.
		req = req.Namespace(l.Namespace)
	}
	err = req.Do().Into(&networkPolicies)
	if err != nil {
		log.WithError(err).Info("Unable to list K8s Network Policy resources")
		return nil, K8sErrorToCalico(err, l)
	}

	// Combine the two resource versions to a single resource version that can be decoded by the Watch.
	// Ideally we would just use the revision from the CRD query as input into the List for the K8s
	// Network Policies.  However, this causes the client request to hang - so it is not a viable option.
	npKvps.Revision = npKvps.Revision + "/" + networkPolicies.ResourceVersion

	// For each policy, turn it into a Policy and generate the list.
	for _, p := range networkPolicies.Items {
		kvp, err := c.converter.K8sNetworkPolicyToCalico(&p)
		if err != nil {
			log.WithError(err).Info("Failed to convert K8s Network Policy")
			return nil, err
		}
		npKvps.KVPairs = append(npKvps.KVPairs, kvp)
	}

	log.WithField("KVPs", npKvps).Info("Returning NP KVPs")
	return npKvps, nil
}

func (c *networkPolicyClient) EnsureInitialized() error {
	return nil
}

func (c *networkPolicyClient) Watch(ctx context.Context, list model.ListInterface, revision string) (api.WatchInterface, error) {
	resl := list.(model.ResourceListOptions)
	if len(resl.Name) != 0 {
		return nil, fmt.Errorf("cannot watch specific resource instance: %s", list.(model.ResourceListOptions).Name)
	}

	// If a revision is specified, see if it contains a "/" and if so split into separate
	// revisions for the CRD and for the K8s resource.
	k8sRev := revision
	crdRev := revision
	if strings.Contains(revision, "/") {
		revs := strings.Split(revision, "/")
		if len(revs) != 2 {
			return nil, fmt.Errorf("badly formatted ResourceVersion: %s", revision)
		}
		crdRev = revs[0]
		k8sRev = revs[1]
	}

	log.WithFields(log.Fields{
		"CRDNPRev": crdRev,
		"K8sNPRev": k8sRev,
	}).Info("Watching two resources at individual revisions")

	k8sWatchClient := cache.NewListWatchFromClient(
		c.clientSet.ExtensionsV1beta1().RESTClient(),
		"networkpolicies",
		resl.Namespace,
		fields.Everything())
	k8sRawWatch, err := k8sWatchClient.WatchFunc(metav1.ListOptions{ResourceVersion: k8sRev})
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
	k8sWatch := newK8sWatcherConverter(ctx, "NetworkPolicy (namespaced)", converter, k8sRawWatch)

	calicoWatch, err := c.crdClient.Watch(ctx, list, crdRev)
	if err != nil {
		k8sWatch.Stop()
		return nil, err
	}

	return newNetworkPolicyWatcher(ctx, k8sWatch, calicoWatch), nil

}

func newNetworkPolicyWatcher(ctx context.Context, k8sWatch, calicoWatch api.WatchInterface) api.WatchInterface {
	ctx, cancel := context.WithCancel(ctx)
	wc := &networkPolicyWatcher{
		k8sNPWatch:    k8sWatch,
		calicoNPWatch: calicoWatch,
		context:       ctx,
		cancel:        cancel,
		resultChan:    make(chan api.WatchEvent, resultsBufSize),
	}
	go wc.processNPEvents()
	return wc
}

type networkPolicyWatcher struct {
	converter     ConvertK8sResourceToKVPair
	k8sNPWatch    api.WatchInterface
	calicoNPWatch api.WatchInterface
	context       context.Context
	cancel        context.CancelFunc
	resultChan    chan api.WatchEvent
	terminated    uint32
}

// Stop stops the watcher and releases associated resources.
// This calls through to the context cancel function.
func (npw *networkPolicyWatcher) Stop() {
	npw.cancel()
	npw.k8sNPWatch.Stop()
	npw.calicoNPWatch.Stop()
}

// ResultChan returns a channel used to receive WatchEvents.
func (npw *networkPolicyWatcher) ResultChan() <-chan api.WatchEvent {
	return npw.resultChan
}

// HasTerminated returns true when the watcher has completed termination processing.
func (npw *networkPolicyWatcher) HasTerminated() bool {
	terminated := atomic.LoadUint32(&npw.terminated) != 0

	if npw.k8sNPWatch != nil {
		terminated = terminated && npw.k8sNPWatch.HasTerminated()
	}
	if npw.calicoNPWatch != nil {
		terminated = terminated && npw.calicoNPWatch.HasTerminated()
	}

	return terminated
}

// Loop to process the events stream from the underlying k8s Watcher and convert them to
// backend KVPs.
func (npw *networkPolicyWatcher) processNPEvents() {
	log.Info("Watcher process started")
	defer func() {
		log.Info("Watcher process terminated")
		npw.Stop()
		close(npw.resultChan)
		atomic.AddUint32(&npw.terminated, 1)
	}()

	for {
		var e api.WatchEvent
		select {
		case e = <-npw.calicoNPWatch.ResultChan():
			log.Debug("Processing Calico NP event")

		case e = <-npw.k8sNPWatch.ResultChan():
			log.Debug("Processing Kubernetes NP event")

		case <-npw.context.Done(): // user cancel
			log.Info("Process watcher done event in kdd client")
			return
		}

		// Send the processed event.
		select {
		case npw.resultChan <- e:
			// If this is an error event, check to see if it's a terminating one.
			// If so, terminate this watcher.
			if e.Type == api.WatchError {
				log.WithError(e.Error).Debug("Kubernetes event converted to backend watcher error event")
				if _, ok := e.Error.(cerrors.ErrorWatchTerminated); ok {
					log.Info("Watch terminated event")
					return
				}
			}

		case <-npw.context.Done():
			log.Info("Process watcher done event during watch event in kdd client")
			return
		}
	}
}
