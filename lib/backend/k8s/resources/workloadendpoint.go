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
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
	kapiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"

	"k8s.io/apimachinery/pkg/types"

	kerrors "k8s.io/apimachinery/pkg/api/errors"

	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/libcalico-go/lib/errors"
)

func NewWorkloadEndpointClient(c kubernetes.Interface) K8sResourceClient {
	return &WorkloadEndpointClient{
		clientSet: c,
		converter: conversion.NewConverter(),
	}
}

// Implements the api.Client interface for WorkloadEndpoints.
type WorkloadEndpointClient struct {
	clientSet kubernetes.Interface
	converter conversion.Converter
}

func (c *WorkloadEndpointClient) Create(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	log.Debug("Received Create request on WorkloadEndpoint type")
	// As a special case for the CNI plugin, try to patch the Pod with the IP that we've calculated.
	// This works around a bug in kubelet that causes it to delay writing the Pod IP for a long time:
	// https://github.com/kubernetes/kubernetes/issues/39113.
	//
	// Note: it's a bit odd to do this in the Create, but the CNI plugin uses CreateOrUpdate().  Doing it
	// here makes sure that, if the update fails: we retry here, and, we don't report success without
	// making the patch.
	return c.patchInPodIPs(ctx, kvp)
}

func (c *WorkloadEndpointClient) Update(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	log.Debug("Received Update request on WorkloadEndpoint type")
	// As a special case for the CNI plugin, try to patch the Pod with the IP that we've calculated.
	// This works around a bug in kubelet that causes it to delay writing the Pod IP for a long time:
	// https://github.com/kubernetes/kubernetes/issues/39113.
	return c.patchInPodIPs(ctx, kvp)
}

func (c *WorkloadEndpointClient) DeleteKVP(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	return c.Delete(ctx, kvp.Key, kvp.Revision, kvp.UID)
}

func (c *WorkloadEndpointClient) Delete(ctx context.Context, key model.Key, revision string, uid *types.UID) (*model.KVPair, error) {
	log.Debug("Delete for WorkloadEndpoint, patching out annotations.")
	return c.patchOutPodIPs(ctx, key, revision, uid)
}

// patchInPodIPs PATCHes the Kubernetes Pod associated with the given KVPair with the IP addresses it contains.
// This is a no-op if there is no IP address.
//
// We store the IP addresses in annotations because patching the PodStatus directly races with changes that
// kubelet makes so kubelet can undo our changes.
func (c *WorkloadEndpointClient) patchInPodIPs(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	ips := kvp.Value.(*apiv3.WorkloadEndpoint).Spec.IPNetworks
	if len(ips) == 0 {
		return kvp, nil
	}

	log.Debugf("PATCHing pod with IPs: %v", ips)
	key := kvp.Key

	// Note: we drop the revision here because the CNI plugin can't handle a retry right now (and the kubelet
	// ensures that only one CNI ADD for a given UID can be in progress).
	return c.patchPodIPAnnotations(ctx, key, "", kvp.UID, ips)
}

// patchOutPodIPs sets our pod IP annotations to empty strings; this is used to signal that the IP has been removed
// from the pod at teardown.
func (c *WorkloadEndpointClient) patchOutPodIPs(ctx context.Context, key model.Key, revision string, uid *types.UID) (*model.KVPair, error) {
	return c.patchPodIPAnnotations(ctx, key, revision, uid, nil)
}

func (c *WorkloadEndpointClient) patchPodIPAnnotations(ctx context.Context, key model.Key, revision string, uid *types.UID, ips []string) (*model.KVPair, error) {
	wepID, err := c.converter.ParseWorkloadEndpointName(key.(model.ResourceKey).Name)
	if err != nil {
		return nil, err
	}
	if wepID.Pod == "" {
		return nil, cerrors.ErrorInsufficientIdentifiers{Name: key.(model.ResourceKey).Name}
	}
	// Write the IP addresses into annotations.  This generates an event more quickly than
	// waiting for kubelet to update the PodStatus PodIP and PodIPs fields.
	ns := key.(model.ResourceKey).Namespace
	firstIP := ""
	if len(ips) > 0 {
		firstIP = ips[0]
	}
	patch, err := calculateAnnotationPatch(
		revision, uid,
		conversion.AnnotationPodIP, firstIP,
		conversion.AnnotationPodIPs, strings.Join(ips, ","),
	)
	if err != nil {
		log.WithError(err).Error("failed to calculate Pod patch.")
		return nil, err
	}
	log.WithField("patch", string(patch)).Debug("Calculated pod patch.")
	pod, err := c.clientSet.CoreV1().Pods(ns).Patch(ctx, wepID.Pod, types.StrategicMergePatchType, patch, metav1.PatchOptions{}, "status")
	if err != nil {
		return nil, K8sErrorToCalico(err, key)
	}
	log.Debugf("Successfully PATCHed pod to set podIP annotation: %+v", pod)

	kvps, err := c.converter.PodToWorkloadEndpoints(pod)
	if err != nil {
		return nil, err
	}

	return kvps[0], nil
}

func calculateAnnotationPatch(revision string, uid *types.UID, namesAndValues ...string) ([]byte, error) {
	patch := map[string]interface{}{}
	metadata := map[string]interface{}{}
	patch["metadata"] = metadata
	annotations := map[string]interface{}{}
	metadata["annotations"] = annotations

	for i := 0; i < len(namesAndValues); i += 2 {
		annotations[namesAndValues[i]] = namesAndValues[i+1]
	}
	if revision != "" {
		// We have a revision.  Since the revision is immutable, if our patch revision doesn't match then the
		// patch will fail.
		log.WithField("rev", revision).Debug("Generating patch for specific rev")
		metadata["resourceVersion"] = revision
	}
	if uid != nil {
		// We have a UID, which identifies a particular instance of a pod with a particular name; add that to
		// the patch.  Since the UID is immutable, if our patch UID doesn't match then the patch will fail.
		log.WithField("uid", *uid).Debug("Generating patch for specific UID")
		metadata["uid"] = uid
	}

	return json.Marshal(patch)
}

func (c *WorkloadEndpointClient) Get(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	log.Debug("Received Get request on WorkloadEndpoint type")
	k := key.(model.ResourceKey)

	// Parse resource name so we can get get the podName
	wepID, err := c.converter.ParseWorkloadEndpointName(key.(model.ResourceKey).Name)
	if err != nil {
		return nil, err
	}
	if wepID.Pod == "" {
		return nil, cerrors.ErrorResourceDoesNotExist{
			Identifier: key,
			Err:        errors.New("malformed WorkloadEndpoint name - unable to determine Pod name"),
		}
	}

	pod, err := c.clientSet.CoreV1().Pods(k.Namespace).Get(ctx, wepID.Pod, metav1.GetOptions{ResourceVersion: revision})
	if err != nil {
		return nil, K8sErrorToCalico(err, k)
	}

	// Decide if this pod should be displayed.
	if !c.converter.IsValidCalicoWorkloadEndpoint(pod) {
		return nil, cerrors.ErrorResourceDoesNotExist{Identifier: k}
	}

	kvps, err := c.converter.PodToWorkloadEndpoints(pod)
	if err != nil {
		return nil, err
	}

	// Find the WorkloadEndpoint that has a name matching the name in the given key
	for _, kvp := range kvps {
		wep := kvp.Value.(*apiv3.WorkloadEndpoint)
		if wep.Name == key.(model.ResourceKey).Name {
			return kvp, nil
		}
	}

	return nil, kerrors.NewNotFound(apiv3.Resource("WorkloadEndpoint"), key.String())
}

func (c *WorkloadEndpointClient) List(ctx context.Context, list model.ListInterface, revision string) (*model.KVPairList, error) {
	log.Debug("Received List request on WorkloadEndpoint type")
	l := list.(model.ResourceListOptions)

	// If a "Name" is provided, we may be able to get the exact WorkloadEndpoint or narrow the WorkloadEndpoints to a
	// single Pod.
	if l.Name != "" {
		return c.listUsingName(ctx, l, revision)
	}

	return c.list(ctx, l, revision)
}

// listUsingName uses the name in the listOptions to retrieve the WorkloadEndpoints. The name, at the very least, must identify
// a single Pod, otherwise an error will occur.
func (c *WorkloadEndpointClient) listUsingName(ctx context.Context, listOptions model.ResourceListOptions, revision string) (*model.KVPairList, error) {
	wepID, err := c.converter.ParseWorkloadEndpointName(listOptions.Name)
	if err != nil {
		return nil, err
	}

	if wepID.Pod == "" {
		return nil, cerrors.ErrorResourceDoesNotExist{
			Identifier: listOptions,
			Err:        errors.New("malformed WorkloadEndpoint name - unable to determine Pod name"),
		}
	}

	pod, err := c.clientSet.CoreV1().Pods(listOptions.Namespace).Get(ctx, wepID.Pod, metav1.GetOptions{ResourceVersion: revision})
	if err != nil {
		if kerrors.IsNotFound(err) {
			return &model.KVPairList{
				KVPairs:  []*model.KVPair{},
				Revision: revision,
			}, nil
		} else {
			return nil, err
		}
	}

	kvps, err := c.converter.PodToWorkloadEndpoints(pod)
	if err != nil {
		return nil, err
	}

	// If Endpoint is available get the single WorkloadEndpoint
	if wepID.Endpoint != "" {
		// Set to an empty list in case a match isn't found
		var tmpKVPs []*model.KVPair

		wepName, err := wepID.CalculateWorkloadEndpointName(false)
		if err != nil {
			return nil, err
		}
		// Find the WorkloadEndpoint that has a name matching the name in the given key
		for _, kvp := range kvps {
			wep := kvp.Value.(*apiv3.WorkloadEndpoint)
			if wep.Name == wepName {
				tmpKVPs = []*model.KVPair{kvp}
				break
			}
		}

		kvps = tmpKVPs
	}

	return &model.KVPairList{
		KVPairs:  kvps,
		Revision: revision,
	}, nil
}

// list lists all the Workload endpoints for the namespace given in listOptions.
func (c *WorkloadEndpointClient) list(ctx context.Context, listOptions model.ResourceListOptions, revision string) (*model.KVPairList, error) {
	podList, err := c.clientSet.CoreV1().Pods(listOptions.Namespace).List(ctx, metav1.ListOptions{ResourceVersion: revision})
	if err != nil {
		return nil, K8sErrorToCalico(err, listOptions)
	}

	// For each Pod, return a workload endpoint.
	var ret []*model.KVPair
	for _, pod := range podList.Items {
		// Decide if this pod should be included.
		if !c.converter.IsValidCalicoWorkloadEndpoint(&pod) {
			continue
		}

		kvps, err := c.converter.PodToWorkloadEndpoints(&pod)
		if err != nil {
			return nil, err
		}
		ret = append(ret, kvps...)
	}

	return &model.KVPairList{
		KVPairs:  ret,
		Revision: revision,
	}, nil
}

func (c *WorkloadEndpointClient) EnsureInitialized() error {
	return nil
}

func (c *WorkloadEndpointClient) Watch(ctx context.Context, list model.ListInterface, revision string) (api.WatchInterface, error) {
	// Build watch options to pass to k8s.
	opts := metav1.ListOptions{ResourceVersion: revision, Watch: true}
	rlo, ok := list.(model.ResourceListOptions)
	if !ok {
		return nil, fmt.Errorf("ListInterface is not a ResourceListOptions: %s", list)
	}
	if len(rlo.Name) != 0 {
		if len(rlo.Namespace) == 0 {
			return nil, errors.New("cannot watch a specific WorkloadEndpoint without a namespace")
		}
		// We've been asked to watch a specific workloadendpoint
		wepids, err := c.converter.ParseWorkloadEndpointName(rlo.Name)
		if err != nil {
			return nil, err
		}
		log.WithField("name", wepids.Pod).Debug("Watching a single workloadendpoint")
		opts.FieldSelector = fields.OneTermEqualSelector("metadata.name", wepids.Pod).String()
	}

	ns := rlo.Namespace
	k8sWatch, err := c.clientSet.CoreV1().Pods(ns).Watch(ctx, opts)
	if err != nil {
		return nil, K8sErrorToCalico(err, list)
	}
	converter := func(r Resource) ([]*model.KVPair, error) {
		k8sPod, ok := r.(*kapiv1.Pod)
		if !ok {
			return nil, errors.New("Pod conversion with incorrect k8s resource type")
		}
		if !c.converter.IsValidCalicoWorkloadEndpoint(k8sPod) {
			// If this is not a valid Calico workload endpoint then don't return in the watch.
			// Returning a nil KVP and a nil error swallows the event.
			return nil, nil
		}
		return c.converter.PodToWorkloadEndpoints(k8sPod)
	}
	return newK8sWatcherConverterOneToMany(ctx, "Pod", converter, k8sWatch), nil
}
