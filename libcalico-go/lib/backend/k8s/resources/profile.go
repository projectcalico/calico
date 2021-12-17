// Copyright (c) 2016-2020 Tigera, Inc. All rights reserved.

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
	"strings"
	"sync/atomic"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	kwatch "k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/resources"
)

func NewProfileClient(c *kubernetes.Clientset) K8sResourceClient {
	return &profileClient{
		clientSet: c,
		Converter: conversion.NewConverter(),
	}
}

// Implements the api.Client interface for Profiles.
type profileClient struct {
	clientSet *kubernetes.Clientset
	conversion.Converter
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

func (c *profileClient) DeleteKVP(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	return c.Delete(ctx, kvp.Key, kvp.Revision, kvp.UID)
}

func (c *profileClient) Delete(ctx context.Context, key model.Key, revision string, uid *types.UID) (*model.KVPair, error) {
	log.Warn("Operation Delete is not supported on Profile type")
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: key,
		Operation:  "Delete",
	}
}

func (c *profileClient) getSaKv(sa *v1.ServiceAccount) (*model.KVPair, error) {
	kvPair, err := c.ServiceAccountToProfile(sa)
	if err != nil {
		return nil, err
	}

	return kvPair, nil
}

func (c *profileClient) getServiceAccount(ctx context.Context, rk model.ResourceKey, revision string) (*model.KVPair, error) {

	namespace, serviceAccountName, err := c.ProfileNameToServiceAccount(rk.Name)
	if err != nil {
		return nil, err
	}

	serviceAccount, err := c.clientSet.CoreV1().ServiceAccounts(namespace).Get(ctx, serviceAccountName, metav1.GetOptions{ResourceVersion: revision})
	if err != nil {
		return nil, K8sErrorToCalico(err, rk)
	}

	return c.getSaKv(serviceAccount)
}

func (c *profileClient) getNsKv(ns *v1.Namespace) (*model.KVPair, error) {
	kvPair, err := c.NamespaceToProfile(ns)
	if err != nil {
		return nil, err
	}

	return kvPair, nil
}

func (c *profileClient) getNamespace(ctx context.Context, rk model.ResourceKey, revision string) (*model.KVPair, error) {
	namespaceName, err := c.ProfileNameToNamespace(rk.Name)
	if err != nil {
		return nil, err
	}

	namespace, err := c.clientSet.CoreV1().Namespaces().Get(ctx, namespaceName, metav1.GetOptions{ResourceVersion: revision})
	if err != nil {
		return nil, K8sErrorToCalico(err, rk)
	}

	return c.getNsKv(namespace)
}

func (c *profileClient) Get(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	log.Debug("Received Get request on Profile type")
	rk := key.(model.ResourceKey)
	if rk.Name == "" {
		return nil, fmt.Errorf("Profile key missing name: %+v", rk)
	} else if rk.Name == resources.DefaultAllowProfileName {
		// Always return the default-allow profile regardless of revision
		return resources.DefaultAllowProfile(), nil
	}

	nsRev, saRev, err := c.SplitProfileRevision(revision)
	if err != nil {
		return nil, err
	}

	splits := strings.SplitAfterN(rk.Name, ".", 2)
	if len(splits) == 1 {
		return nil, fmt.Errorf("Invalid name %s", rk.Name)
	}

	switch splits[0] {
	case conversion.NamespaceProfileNamePrefix:
		return c.getNamespace(ctx, rk, nsRev)
	case conversion.ServiceAccountProfileNamePrefix:
		return c.getServiceAccount(ctx, rk, saRev)
	}

	return nil, fmt.Errorf("Revision %s invalid", revision)
}

func (c *profileClient) List(ctx context.Context, list model.ListInterface, revision string) (*model.KVPairList, error) {
	logContext := log.WithField("Resource", "Profile")
	logContext.Debug("Received List request")
	nl := list.(model.ResourceListOptions)

	// If a name is specified, then do an exact lookup.
	if nl.Name != "" {
		kvps := []*model.KVPair{}
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
			KVPairs:  kvps,
			Revision: revision,
		}, nil
	}

	nsRev, saRev, err := c.SplitProfileRevision(revision)
	if err != nil {
		return nil, err
	}

	// Enumerate all namespaces, paginated.
	listFunc := func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
		return c.clientSet.CoreV1().Namespaces().List(ctx, opts)
	}
	convertFunc := func(r Resource) ([]*model.KVPair, error) {
		ns := r.(*v1.Namespace)
		kvp, err := c.getNsKv(ns)
		if err != nil {
			return nil, err
		}
		return []*model.KVPair{kvp}, nil
	}
	nsKVPs, err := pagedList(ctx, logContext.WithField("from", "namespaces"), nsRev, list, convertFunc, listFunc)
	if err != nil {
		return nil, err
	}

	// Enumerate all service accounts, paginated.
	listFunc = func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
		return c.clientSet.CoreV1().ServiceAccounts(v1.NamespaceAll).List(ctx, opts)
	}
	convertFunc = func(r Resource) ([]*model.KVPair, error) {
		sa := r.(*v1.ServiceAccount)
		kvp, err := c.getSaKv(sa)
		if err != nil {
			return nil, err
		}
		return []*model.KVPair{kvp}, nil
	}
	saKVPs, err := pagedList(ctx, logContext.WithField("from", "serviceaccounts"), saRev, list, convertFunc, listFunc)
	if err != nil {
		return nil, err
	}

	// Return a merged KVPairList including both results as well as the default-allow profile.
	kvps := append([]*model.KVPair{resources.DefaultAllowProfile()}, nsKVPs.KVPairs...)
	kvps = append(kvps, saKVPs.KVPairs...)
	return &model.KVPairList{
		KVPairs:  kvps,
		Revision: c.JoinProfileRevisions(nsKVPs.Revision, saKVPs.Revision),
	}, nil
}

func (c *profileClient) EnsureInitialized() error {
	return nil
}

func (c *profileClient) Watch(ctx context.Context, list model.ListInterface, revision string) (api.WatchInterface, error) {
	// Build watch options to pass to k8s.
	opts := metav1.ListOptions{Watch: true, AllowWatchBookmarks: false}
	rlo, ok := list.(model.ResourceListOptions)
	if !ok {
		return nil, fmt.Errorf("ListInterface is not a ResourceListOptions: %s", list)
	}

	// Setting to Watch all profiles in all namespaces; overridden below
	watchNS, watchSA := true, true
	ns := v1.NamespaceAll
	sa := ""

	// Watch a specific profile.
	if len(rlo.Name) != 0 {
		log.WithField("name", rlo.Name).Debug("Watching a single profile")
		var err error

		// If we're watching the default-allow profile by name, then we exit
		// with a new profileWatcher now and use fake watches in place
		// of real ns and sa watchers. This profile watcher will never get any
		// events because no events will occur for the static default-allow profile.
		if rlo.Name == resources.DefaultAllowProfileName {
			log.WithField("rv", revision).Debug("Creating a fake watch on default-allow profile")
			return newProfileWatcher(ctx, api.NewFake(), api.NewFake()), nil
		} else if strings.HasPrefix(rlo.Name, conversion.NamespaceProfileNamePrefix) {
			watchSA = false
			ns, err = c.ProfileNameToNamespace(rlo.Name)
			if err != nil {
				return nil, err
			}
			opts.FieldSelector = fields.OneTermEqualSelector("metadata.name", ns).String()
		} else if strings.HasPrefix(rlo.Name, conversion.ServiceAccountProfileNamePrefix) {
			watchNS = false
			ns, sa, err = c.ProfileNameToServiceAccount(rlo.Name)
			if err != nil {
				return nil, err
			}
			opts.FieldSelector = fields.OneTermEqualSelector("metadata.name", sa).String()
		} else {
			return nil, fmt.Errorf("Unsupported prefix for resource name: %s", rlo.Name)
		}
	}
	nsRev, saRev, err := c.SplitProfileRevision(revision)
	if err != nil {
		return nil, err
	}

	opts.ResourceVersion = nsRev
	var nsWatch kwatch.Interface = kwatch.NewFake()
	if watchNS {
		log.Debugf("Watching namespace at revision %q", nsRev)
		nsWatch, err = c.clientSet.CoreV1().Namespaces().Watch(ctx, opts)
		if err != nil {
			return nil, K8sErrorToCalico(err, list)
		}
	}
	converter := func(r Resource) (*model.KVPair, error) {
		k8sNamespace, ok := r.(*v1.Namespace)
		if !ok {
			return nil, errors.New("Profile conversion with incorrect k8s resource type")
		}
		return c.NamespaceToProfile(k8sNamespace)
	}
	nsWatcher := newK8sWatcherConverter(ctx, "Profile-NS", converter, nsWatch)

	// Watch all service accounts in relevant namespace(s)
	opts.ResourceVersion = saRev
	var saWatch kwatch.Interface = kwatch.NewFake()
	if watchSA {
		log.Debugf("Watching serviceAccount at revision %q", saRev)
		saWatch, err = c.clientSet.CoreV1().ServiceAccounts(ns).Watch(ctx, opts)
		if err != nil {
			nsWatch.Stop()
			return nil, K8sErrorToCalico(err, list)
		}
	}
	converterSA := func(r Resource) (*model.KVPair, error) {
		k8sServiceAccount, ok := r.(*v1.ServiceAccount)
		if !ok {
			nsWatch.Stop()
			return nil, errors.New("Profile conversion with incorrect k8s resource type")
		}
		return c.ServiceAccountToProfile(k8sServiceAccount)
	}
	saWatcher := newK8sWatcherConverter(ctx, "Profile-SA", converterSA, saWatch)

	return newProfileWatcher(ctx, nsWatcher, saWatcher), nil
}

func newProfileWatcher(ctx context.Context, k8sWatchNS, k8sWatchSA api.WatchInterface) api.WatchInterface {
	ctx, cancel := context.WithCancel(ctx)
	wc := &profileWatcher{
		k8sNSWatch: k8sWatchNS,
		k8sSAWatch: k8sWatchSA,
		context:    ctx,
		cancel:     cancel,
		resultChan: make(chan api.WatchEvent, resultsBufSize),
		Converter:  conversion.NewConverter(),
	}
	go wc.processProfileEvents()
	return wc
}

type profileWatcher struct {
	conversion.Converter
	converter  ConvertK8sResourceToKVPair
	k8sNSWatch api.WatchInterface
	k8sSAWatch api.WatchInterface
	k8sNSRev   string
	k8sSARev   string
	context    context.Context
	cancel     context.CancelFunc
	resultChan chan api.WatchEvent
	terminated uint32
}

// Stop stops the watcher and releases associated resources.
// This calls through the context cancel function.
func (pw *profileWatcher) Stop() {
	pw.cancel()
	pw.k8sNSWatch.Stop()
	pw.k8sSAWatch.Stop()
}

// ResultChan returns a channel used to receive WatchEvents.
func (pw *profileWatcher) ResultChan() <-chan api.WatchEvent {
	return pw.resultChan
}

// HasTerminated returns true when the watcher has completed termination processing.
func (pw *profileWatcher) HasTerminated() bool {
	terminated := atomic.LoadUint32(&pw.terminated) != 0

	if pw.k8sNSWatch != nil {
		terminated = terminated && pw.k8sNSWatch.HasTerminated()
	}
	if pw.k8sSAWatch != nil {
		terminated = terminated && pw.k8sSAWatch.HasTerminated()
	}

	return terminated
}

// Loop to process the events stream from the underlying k8s Watcher and convert them to
// backend KVPs.
func (pw *profileWatcher) processProfileEvents() {
	log.Debug("Watcher process started for profile.")
	defer func() {
		log.Debug("Profile watcher process terminated")
		pw.Stop()
		close(pw.resultChan)
		atomic.AddUint32(&pw.terminated, 1)
	}()

	for {
		var ok bool
		var e api.WatchEvent
		var isNsEvent bool
		select {
		case e, ok = <-pw.k8sNSWatch.ResultChan():
			if !ok {
				// Watch channel is closed by upstream hence, return from loop.
				log.Debug("Profile, namespace watch channel closed by remote.")
				return
			}
			log.Debug("Processing Namespace event")
			isNsEvent = true

		case e, ok = <-pw.k8sSAWatch.ResultChan():
			if !ok {
				// Watch channel is closed by upstream hence, return from loop.
				log.Debug("Profile, serviceaccount watch channel closed by remote.")
				return
			}
			log.Debug("Processing ServiceAccount event")
			isNsEvent = false

		case <-pw.context.Done(): //user cancel
			log.Debug("Process watcher done event in kdd client")
			return
		}

		// Update the resource version of the Object in the watcher. The version returned on a watch
		// event needs to be such that the Watch client can resume watching when a watch fails.
		// The watch client expects a slash separated list of resource versions in the format
		// <NS Revision/SA Revision>.
		var value interface{}
		switch e.Type {
		case api.WatchModified, api.WatchAdded:
			value = e.New.Value
		case api.WatchDeleted:
			value = e.Old.Value
		}

		if value != nil {
			oma, ok := value.(metav1.ObjectMetaAccessor)

			if !ok {
				log.WithField("event", e).Error(
					"Resource returned from watch does not implement ObjectMetaAccessor interface")
				// handle this Error as a Watcher termination by remote.
				return
			} else {
				if isNsEvent {
					pw.k8sNSRev = oma.GetObjectMeta().GetResourceVersion()
				} else {
					pw.k8sSARev = oma.GetObjectMeta().GetResourceVersion()
				}
				oma.GetObjectMeta().SetResourceVersion(pw.JoinProfileRevisions(pw.k8sNSRev, pw.k8sSARev))
			}
		} else if e.Error == nil {
			log.WithField("event", e).Warning("Event without error or value")
		}

		// Send the processed event.
		select {
		case pw.resultChan <- e:
			// If this is an error event. bubble up the error event.
			if e.Type == api.WatchError {
				log.Debug("Kubernetes event converted to backend watcher error event")
			}

		case <-pw.context.Done():
			log.Debug("Process watcher done event during watch event in kdd client")
			return
		}
	}
}
