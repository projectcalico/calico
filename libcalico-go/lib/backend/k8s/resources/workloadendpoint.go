// Copyright (c) 2016-2021 Tigera, Inc. All rights reserved.

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

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/json"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
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
	return c.patchInAnnotations(ctx, kvp, "Create")
}

func (c *WorkloadEndpointClient) Update(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	log.Debug("Received Update request on WorkloadEndpoint type")
	// As a special case for the CNI plugin, try to patch the Pod with the IP that we've calculated.
	// This works around a bug in kubelet that causes it to delay writing the Pod IP for a long time:
	// https://github.com/kubernetes/kubernetes/issues/39113.
	return c.patchInAnnotations(ctx, kvp, "Update")
}

func (c *WorkloadEndpointClient) DeleteKVP(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	return c.Delete(ctx, kvp.Key, kvp.Revision, kvp.UID)
}

func (c *WorkloadEndpointClient) Delete(
	ctx context.Context,
	key model.Key,
	revision string,
	uid *types.UID,
) (*model.KVPair, error) {
	log.Debug("Delete for WorkloadEndpoint, patching out annotations.")
	return c.patchOutAnnotations(ctx, key, revision, uid)
}

// patchInAnnotations PATCHes the Kubernetes Pod associated with the given KVPair with the IP addresses it contains.
// This is a no-op if there is no IP address.
//
// We store the IP addresses in annotations because patching the PodStatus directly races with changes that
// kubelet makes so kubelet can undo our changes.
func (c *WorkloadEndpointClient) patchInAnnotations(
	ctx context.Context,
	kvp *model.KVPair,
	operation string,
) (*model.KVPair, error) {
	var annotations map[string]string
	var revision string
	patchMode := PatchModeOf(ctx)
	switch patchMode {
	case PatchModeCNI:
		annotations = c.calcCNIAnnotations(kvp)
		// Note: we drop the revision here because the CNI plugin can't handle a retry right now (and the kubelet
		// ensures that only one CNI ADD for a given UID can be in progress).
		revision = ""
	default:
		return nil, cerrors.ErrorOperationNotSupported{
			Identifier: kvp.Key,
			Operation:  operation,
			Reason:     fmt.Sprintf("unsupported PatchMode: %s", patchMode),
		}
	}
	return c.patchPodAnnotations(ctx, kvp.Key, revision, kvp.UID, annotations)
}

func (c *WorkloadEndpointClient) calcCNIAnnotations(kvp *model.KVPair) map[string]string {
	annotations := make(map[string]string)
	wep := kvp.Value.(*libapiv3.WorkloadEndpoint)
	ips := wep.Spec.IPNetworks
	if len(ips) == 0 {
		return annotations
	}
	log.Debugf("PATCHing pod with IPs: %v", ips)

	// Write the IP addresses into annotations.  This generates an event more quickly than
	// waiting for kubelet to update the PodStatus PodIP and PodIPs fields.
	firstIP := ""
	if len(ips) > 0 {
		firstIP = ips[0]
	}
	annotations[conversion.AnnotationPodIP] = firstIP
	annotations[conversion.AnnotationPodIPs] = strings.Join(ips, ",")

	containerID := wep.Spec.ContainerID
	if containerID != "" {
		log.WithField("containerID", containerID).Debug("Container ID specified, including in patch")
		annotations[conversion.AnnotationContainerID] = containerID
	}
	return annotations
}

// patchOutAnnotations sets our pod IP annotations to empty strings; this is used to signal that the IP has been removed
// from the pod at teardown.
func (c *WorkloadEndpointClient) patchOutAnnotations(
	ctx context.Context,
	key model.Key,
	revision string,
	uid *types.UID,
) (*model.KVPair, error) {
	// Passing nil for annotations will result in all annotations being explicitly set to the empty string.
	// Setting the podIPs to empty string is used to signal that the CNI DEL has removed the IP from the Pod.
	// We leave the container ID in place to allow any repeat invocations of the CNI DEL to tell which instance of a Pod they are seeing.
	annotations := map[string]string{
		conversion.AnnotationPodIP:  "",
		conversion.AnnotationPodIPs: "",
	}
	return c.patchPodAnnotations(ctx, key, revision, uid, annotations)
}

func (c *WorkloadEndpointClient) patchPodAnnotations(
	ctx context.Context,
	key model.Key,
	revision string,
	uid *types.UID,
	annotations map[string]string,
) (*model.KVPair, error) {
	wepID, err := c.converter.ParseWorkloadEndpointName(key.(model.ResourceKey).Name)
	if err != nil {
		return nil, err
	}
	if wepID.Pod == "" {
		return nil, cerrors.ErrorInsufficientIdentifiers{Name: key.(model.ResourceKey).Name}
	}
	ns := key.(model.ResourceKey).Namespace
	patch, err := calculateAnnotationPatch(revision, uid, annotations)
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

func calculateAnnotationPatch(revision string, uid *types.UID, annotations map[string]string) ([]byte, error) {
	patch := map[string]interface{}{}
	metadata := map[string]interface{}{}
	patch["metadata"] = metadata
	if len(annotations) > 0 {
		metadata["annotations"] = annotations
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

	// Parse resource name so we can get the podName
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
		wep := kvp.Value.(*libapiv3.WorkloadEndpoint)
		if wep.Name == key.(model.ResourceKey).Name {
			return kvp, nil
		}
	}

	return nil, cerrors.ErrorResourceDoesNotExist{Identifier: k}
}

type workloadEndpointClientContextOption string

var workloadEndpointClientContextOptionListMode workloadEndpointClientContextOption = "ListMode"

type WorkloadEndpointListMode string

const (
	WorkloadEndpointListModeForceGet WorkloadEndpointListMode = "UseGet"
)

func ContextWithWorkloadEndpointListMode(ctx context.Context, mode WorkloadEndpointListMode) context.Context {
	return context.WithValue(ctx, workloadEndpointClientContextOptionListMode, mode)
}

func (c *WorkloadEndpointClient) List(
	ctx context.Context,
	list model.ListInterface,
	revision string,
) (*model.KVPairList, error) {
	logContext := log.WithField("Resource", "WorkloadEndpoint")
	logContext.Debug("Received List request")
	l := list.(model.ResourceListOptions)

	var wepID names.WorkloadEndpointIdentifiers
	if l.Name != "" {
		if ctx.Value(workloadEndpointClientContextOptionListMode) == WorkloadEndpointListModeForceGet {
			// Special case for the CNI plugin, which only has permissions to
			// get single pods, and doesn't need to watch the pod.
			log.Debug("Caller opted in to use a Get instead of a List.")
			return c.listUsingName(ctx, l, revision)
		}

		var err error
		wepID, err = c.converter.ParseWorkloadEndpointName(l.Name)
		if err != nil {
			return nil, err
		}
		if wepID.Pod == "" {
			return nil, cerrors.ErrorResourceDoesNotExist{
				Identifier: l,
				Err:        errors.New("malformed WorkloadEndpoint name - unable to determine Pod name"),
			}
		}
	}

	// Perform a paginated list of pods, executing the conversion function on each.
	listFunc := func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
		if wepID.Pod != "" {
			// Asked for a specific pod, filter on name.
			opts.FieldSelector = fields.OneTermEqualSelector("metadata.name", wepID.Pod).String()
		}

		podList, err := c.clientSet.CoreV1().Pods(l.Namespace).List(ctx, opts)
		if err != nil {
			return nil, err
		}

		return podList, nil
	}

	return pagedList(ctx, logContext, revision, list, c.convertAndFilterPodFn(wepID), listFunc)
}

// listUsingName uses the name in the listOptions to retrieve the WorkloadEndpoints. The name must identify
// a single Pod, otherwise an error will occur.
func (c *WorkloadEndpointClient) listUsingName(
	ctx context.Context,
	listOptions model.ResourceListOptions,
	revision string,
) (*model.KVPairList, error) {
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
			wep := kvp.Value.(*libapiv3.WorkloadEndpoint)
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

func (c *WorkloadEndpointClient) EnsureInitialized() error {
	return nil
}

func (c *WorkloadEndpointClient) Watch(
	ctx context.Context,
	list model.ListInterface,
	options api.WatchOptions,
) (api.WatchInterface, error) {
	// Build watch options to pass to k8s.
	rlo, ok := list.(model.ResourceListOptions)
	if !ok {
		return nil, fmt.Errorf("ListInterface is not a ResourceListOptions: %s", list)
	}
	k8sOpts := watchOptionsToK8sListOptions(options)
	var wepID names.WorkloadEndpointIdentifiers
	if len(rlo.Name) != 0 {
		if len(rlo.Namespace) == 0 {
			return nil, errors.New("cannot watch a specific WorkloadEndpoint without a namespace")
		}
		// We've been asked to watch a specific workloadendpoint
		var err error
		wepID, err = c.converter.ParseWorkloadEndpointName(rlo.Name)
		if err != nil {
			return nil, err
		}
		log.WithField("name", wepID.Pod).Debug("Watching a single workloadendpoint")
		k8sOpts.FieldSelector = fields.OneTermEqualSelector("metadata.name", wepID.Pod).String()
	}

	k8sWatch, err := c.clientSet.CoreV1().Pods(rlo.Namespace).Watch(ctx, k8sOpts)
	if err != nil {
		return nil, K8sErrorToCalico(err, list)
	}
	return newK8sWatcherConverterOneToMany(ctx, "Pod", c.convertAndFilterPodFn(wepID), k8sWatch), nil
}

func (c *WorkloadEndpointClient) convertAndFilterPodFn(wepID names.WorkloadEndpointIdentifiers) func(r Resource) ([]*model.KVPair, error) {
	return func(r Resource) ([]*model.KVPair, error) {
		pod := r.(*v1.Pod)

		// Decide if this pod should be included.
		if !c.converter.IsValidCalicoWorkloadEndpoint(pod) {
			return nil, nil
		}

		// Convert to WorkloadEndpoint.
		weps, err := c.converter.PodToWorkloadEndpoints(pod)
		if err != nil {
			return nil, err
		}

		// Now we have the WorkloadEndpoint, filter based on the endpoint name
		// if requested.
		if wepID.Endpoint != "" {
			// We were asked for a specific endpoint within the pod.
			wepName, err := wepID.CalculateWorkloadEndpointName(false)
			if err != nil {
				return nil, err
			}
			for _, wep := range weps {
				if wep.Value.(*libapiv3.WorkloadEndpoint).Name != wepName {
					continue
				}
				return []*model.KVPair{wep}, nil
			}
			return nil, nil
		}

		return weps, nil
	}
}
