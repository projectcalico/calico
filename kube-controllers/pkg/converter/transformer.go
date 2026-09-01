// Copyright (c) 2017-2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package converter

import (
	"fmt"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
)

// calicoNodeContainerName identifies a calico-node pod. The pod label varies by install flavour
// (Canal uses "canal"), but every flavour names the container calico-node.
const calicoNodeContainerName = "calico-node"

// IsCalicoNodePod reports whether the pod is a calico-node pod managed by a DaemonSet. It works
// on both full pods and the slimmed-down copies PodTransformer puts in the kube-controllers cache.
func IsCalicoNodePod(pod *v1.Pod) bool {
	if !ownedByDaemonSet(pod) {
		return false
	}
	for _, container := range pod.Spec.Containers {
		if container.Name == calicoNodeContainerName {
			return true
		}
	}
	return false
}

func ownedByDaemonSet(pod *v1.Pod) bool {
	for _, ref := range pod.OwnerReferences {
		if ref.Kind == "DaemonSet" {
			return true
		}
	}
	return false
}

// podTransformer is passed to the pod informer used by kube-controllers in order to reduce the amount of
// memory used by the pod cache.  It takes a full v1.Pod and returns a slimmed down version of the pod
// that only contains the fields we care about.
func PodTransformer(podControllerEnabled bool) cache.TransformFunc {
	return func(a any) (any, error) {
		pod, ok := a.(*v1.Pod)
		if !ok {
			return nil, fmt.Errorf("expected *v1.Pod, got %T", a)
		}

		p := &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      pod.Name,
				Namespace: pod.Namespace,
				UID:       pod.UID,
			},
			Spec: v1.PodSpec{
				NodeName:    pod.Spec.NodeName,
				HostNetwork: pod.Spec.HostNetwork,
			},
			Status: v1.PodStatus{
				// Strictly speaking, we could probably get away with just using PodIPs here,
				// but better to be safe than sorry.
				PodIP:  pod.Status.PodIP,
				PodIPs: pod.Status.PodIPs,
				Phase:  pod.Status.Phase,
			},
		}

		if podControllerEnabled {
			// The Pod controller needs the full label set and service account name, as they
			// are sync'd to etcd for policy matching.
			p.Labels = pod.Labels
			p.Spec.ServiceAccountName = pod.Spec.ServiceAccountName
		}

		if IsCalicoNodePod(pod) {
			// Keep the few fields the node condition controller reads, and only for the pods it
			// reads them from - a Ready condition per pod across the cluster is not worth caching.
			p.OwnerReferences = pod.OwnerReferences
			p.Spec.Containers = []v1.Container{{Name: calicoNodeContainerName}}
			for _, cond := range pod.Status.Conditions {
				if cond.Type == v1.PodReady {
					p.Status.Conditions = []v1.PodCondition{cond}
					break
				}
			}
		}

		// Include the annotations we care about, if they exist.
		if pod.Annotations != nil {
			for _, annotation := range []string{
				conversion.AnnotationPodIP,
				conversion.AnnotationPodIPs,
				conversion.AnnotationAWSPodIPs,
			} {
				if value, ok := pod.Annotations[annotation]; ok {
					if p.Annotations == nil {
						p.Annotations = make(map[string]string)
					}
					p.Annotations[annotation] = value
				}
			}
		}

		return p, nil
	}
}
