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

	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"

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
	log.Warn("Operation Create is not supported on WorkloadEndpoint type")
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: kvp.Key,
		Operation:  "Create",
	}
}

func (c *WorkloadEndpointClient) Update(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	log.Warn("Operation Update is not supported on WorkloadEndpoint type")
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: kvp.Key,
		Operation:  "Create",
	}
}

func (c *WorkloadEndpointClient) Delete(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	log.Warn("Operation Delete is not supported on WorkloadEndpoint type")
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: key,
		Operation:  "Delete",
	}
}

func (c *WorkloadEndpointClient) Get(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	log.Warn("Operation Get is not supported on WorkloadEndpoint type")
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: key,
		Operation:  "Get",
	}
}

func (c *WorkloadEndpointClient) List(ctx context.Context, list model.ListInterface, revision string) (*model.KVPairList, error) {
	log.Warn("Operation List is not supported on WorkloadEndpoint type")
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: list,
		Operation:  "List",
	}
}

func (c *WorkloadEndpointClient) EnsureInitialized() error {
	return nil
}

func (c *WorkloadEndpointClient) Watch(ctx context.Context, list model.ListInterface, revision string) (api.WatchInterface, error) {
	log.Warn("Operation Watch is not supported on WorkloadEndpoint type")
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: list,
		Operation:  "Watch",
	}
}

/*

// applyWorkloadEndpoint patches the existing Pod to include an IP address, if
// one has been set on the workload endpoint.
// TODO: This is only required as a workaround for an upstream k8s issue.  Once fixed,
// this should be a no-op. See https://github.com/kubernetes/kubernetes/issues/39113
func (c *KubeClient) applyWorkloadEndpoint(k *model.KVPair) (*model.KVPair, error) {
	ips := k.Value.(*model.WorkloadEndpoint).IPv4Nets
	if len(ips) > 0 {
		log.Debugf("Applying workload with IPs: %+v", ips)
		ns, name := c.converter.ParseWorkloadID(k.Key.(model.WorkloadEndpointKey).WorkloadID)
		pod, err := c.clientSet.Pods(ns).Get(name, metav1.GetOptions{})
		if err != nil {
			return nil, resources.K8sErrorToCalico(err, k.Key)
		}
		pod.Status.PodIP = ips[0].IP.String()
		pod, err = c.clientSet.Pods(ns).UpdateStatus(pod)
		if err != nil {
			return nil, resources.K8sErrorToCalico(err, k.Key)
		}
		log.Debugf("Successfully applied pod: %+v", pod)
		return c.converter.PodToWorkloadEndpoint(pod)
	}
	return k, nil
}

// listWorkloadEndpoints lists WorkloadEndpoints from the k8s API based on existing Pods.
func (c *KubeClient) listWorkloadEndpoints(ctx context.Context, l model.ResourceListOptions, revision string) (*model.KVPairList, error) {
	// If a workload is provided, we can do an exact lookup of this
	// workload endpoint.
	if l.Name != "" {
		kvp, err := c.getWorkloadEndpoint(ctx, model.ResourceKey{
			Name: l.Name,
			Kind: l.Kind,
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

	// Otherwise, enumerate all pods in all namespaces.
	// We don't yet support hostname, orchestratorID, for the k8s backend.
	pods, err := c.clientSet.Pods("").List(metav1.ListOptions{})
	if err != nil {
		return nil, resources.K8sErrorToCalico(err, l)
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

// getWorkloadEndpoint gets the WorkloadEndpoint from the k8s API based on existing Pods.
func (c *KubeClient) getWorkloadEndpoint(ctx context.Context, k model.ResourceKey, revision string) (*model.KVPair, error) {
	// The workloadID is of the form namespace.podname.  Parse it so we
	// can find the correct namespace to get the pod.
	namespace, podName := c.converter.ParseWorkloadID(k.Name)

	pod, err := c.clientSet.Pods(namespace).Get(podName, metav1.GetOptions{})
	if err != nil {
		return nil, resources.K8sErrorToCalico(err, k)
	}

	// Decide if this pod should be displayed.
	if !c.converter.IsReadyCalicoPod(pod) {
		return nil, cerrors.ErrorResourceDoesNotExist{Identifier: k}
	}
	return c.converter.PodToWorkloadEndpoint(pod)
}

*/
