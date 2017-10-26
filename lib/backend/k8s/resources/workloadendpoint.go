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
	kapiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	apiv2 "github.com/projectcalico/libcalico-go/lib/apis/v2"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/libcalico-go/lib/errors"
)

func NewWorkloadEndpointClient(c *kubernetes.Clientset) K8sResourceClient {
	return &WorkloadEndpointClient{
		clientSet: c,
	}
}

// Implements the api.Client interface for WorkloadEndpoints.
type WorkloadEndpointClient struct {
	clientSet *kubernetes.Clientset
	converter conversion.Converter
}

func (c *WorkloadEndpointClient) Create(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	log.Debug("Received Create request on WorkloadEndpoint type")

	// We only patch the existing Pod to include an IP address, if one has been
	// set on the workload endpoint.
	// TODO: This is only required as a workaround for an upstream k8s issue.  Once fixed,
	// this should be a no-op. See https://github.com/kubernetes/kubernetes/issues/39113
	ips := kvp.Value.(*apiv2.WorkloadEndpoint).Spec.IPNetworks
	if len(ips) > 0 {
		log.Debugf("Applying workload with IPs: %+v", ips)
		wepID, err := c.converter.ParseWorkloadEndpointName(kvp.Key.(model.ResourceKey).Name)
		if err != nil {
			return nil, err
		}
		if wepID.Pod == "" {
			return nil, cerrors.ErrorInsufficientIdentifiers{Name: kvp.Key.(model.ResourceKey).Name}
		}
		ns := kvp.Key.(model.ResourceKey).Namespace
		pod, err := c.clientSet.CoreV1().Pods(ns).Get(wepID.Pod, metav1.GetOptions{})
		if err != nil {
			return nil, K8sErrorToCalico(err, kvp.Key)
		}
		pod.Status.PodIP = ips[0]
		pod, err = c.clientSet.CoreV1().Pods(ns).UpdateStatus(pod)
		if err != nil {
			return nil, K8sErrorToCalico(err, kvp.Key)
		}
		log.Debugf("Successfully applied pod: %+v", pod)
		return c.converter.PodToWorkloadEndpoint(pod)
	}
	return kvp, nil
}

func (c *WorkloadEndpointClient) Update(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	log.Debug("Received Update request on WorkloadEndpoint type")

	// We only patch the existing Pod to include an IP address, if one has been
	// set on the workload endpoint.
	// TODO: This is only required as a workaround for an upstream k8s issue.  Once fixed,
	// this should be a no-op. See https://github.com/kubernetes/kubernetes/issues/39113
	ips := kvp.Value.(*apiv2.WorkloadEndpoint).Spec.IPNetworks
	if len(ips) > 0 {
		log.Debugf("Applying workload with IPs: %+v", ips)
		wepID, err := c.converter.ParseWorkloadEndpointName(kvp.Key.(model.ResourceKey).Name)
		if err != nil {
			return nil, err
		}
		if wepID.Pod == "" {
			return nil, cerrors.ErrorInsufficientIdentifiers{Name: kvp.Key.(model.ResourceKey).Name}
		}
		ns := kvp.Key.(model.ResourceKey).Namespace
		pod, err := c.clientSet.CoreV1().Pods(ns).Get(wepID.Pod, metav1.GetOptions{})
		if err != nil {
			return nil, K8sErrorToCalico(err, kvp.Key)
		}
		pod.Status.PodIP = ips[0]
		pod, err = c.clientSet.CoreV1().Pods(ns).UpdateStatus(pod)
		if err != nil {
			return nil, K8sErrorToCalico(err, kvp.Key)
		}
		log.Debugf("Successfully applied pod: %+v", pod)
		return c.converter.PodToWorkloadEndpoint(pod)
	}
	return kvp, nil
}

func (c *WorkloadEndpointClient) Delete(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	log.Warn("Operation Delete is not supported on WorkloadEndpoint type")
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: key,
		Operation:  "Delete",
	}
}

func (c *WorkloadEndpointClient) Get(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	log.Debug("Received Get request on WorkloadEndpoint type")
	k := key.(model.ResourceKey)

	// Parse resource name so we can get get the podName
	wepID, err := c.converter.ParseWorkloadEndpointName(key.(model.ResourceKey).Name)
	if err != nil {
		return nil, err
	}

	pod, err := c.clientSet.CoreV1().Pods(k.Namespace).Get(wepID.Pod, metav1.GetOptions{ResourceVersion: revision})
	if err != nil {
		return nil, K8sErrorToCalico(err, k)
	}

	// Decide if this pod should be displayed.
	if !c.converter.IsReadyCalicoPod(pod) {
		return nil, cerrors.ErrorResourceDoesNotExist{Identifier: k}
	}
	return c.converter.PodToWorkloadEndpoint(pod)
}

func (c *WorkloadEndpointClient) List(ctx context.Context, list model.ListInterface, revision string) (*model.KVPairList, error) {
	log.Debug("Received List request on WorkloadEndpoint type")
	l := list.(model.ResourceListOptions)

	// If a workload is provided, we can do an exact lookup of this
	// workload endpoint.
	if l.Name != "" {
		kvp, err := c.Get(ctx, model.ResourceKey{
			Name:      l.Name,
			Namespace: l.Namespace,
			Kind:      l.Kind,
		}, revision)
		if err != nil {
			switch err.(type) {
			// Return empty slice of KVPair if the object doesn't exist, return the error otherwise.
			case cerrors.ErrorResourceDoesNotExist:
				return &model.KVPairList{
					KVPairs:  []*model.KVPair{},
					Revision: revision,
				}, nil
			default:
				return nil, err
			}
		}

		return &model.KVPairList{
			KVPairs:  []*model.KVPair{kvp},
			Revision: revision,
		}, nil
	}

	// Otherwise, enumerate all pods in a namespace.
	pods, err := c.clientSet.CoreV1().Pods(l.Namespace).List(metav1.ListOptions{ResourceVersion: revision})
	if err != nil {
		return nil, K8sErrorToCalico(err, l)
	}

	// For each Pod, return a workload endpoint.
	ret := []*model.KVPair{}
	for _, pod := range pods.Items {
		// Decide if this pod should be displayed.
		if !c.converter.IsReadyCalicoPod(&pod) {
			continue
		}

		kvp, err := c.converter.PodToWorkloadEndpoint(&pod)
		if err != nil {
			return nil, err
		}
		ret = append(ret, kvp)
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
	if len(list.(model.ResourceListOptions).Name) != 0 {
		return nil, fmt.Errorf("cannot watch specific resource instance: %s", list.(model.ResourceListOptions).Name)
	}

	ns := list.(model.ResourceListOptions).Namespace
	k8sWatch, err := c.clientSet.CoreV1().Pods(ns).Watch(metav1.ListOptions{ResourceVersion: revision})
	if err != nil {
		return nil, K8sErrorToCalico(err, list)
	}
	converter := func(r Resource) (*model.KVPair, error) {
		k8sPod, ok := r.(*kapiv1.Pod)
		if !ok {
			return nil, errors.New("Pod conversion with incorrect k8s resource type")
		}
		return c.converter.PodToWorkloadEndpoint(k8sPod)
	}
	return newK8sWatcherConverter(ctx, "Pod", converter, k8sWatch), nil
}
