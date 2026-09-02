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
	"slices"

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

// calicoNodeCachedEnv is the calico-node environment the node condition controller reads. The
// rest is dropped, since calico-node carries a few dozen variables per pod.
var calicoNodeCachedEnv = []string{"CALICO_NETWORKING_BACKEND"}

func keptCalicoNodeEnv(pod *v1.Pod) []v1.EnvVar {
	var kept []v1.EnvVar
	for _, container := range pod.Spec.Containers {
		if container.Name != calicoNodeContainerName {
			continue
		}
		for _, env := range container.Env {
			if slices.Contains(calicoNodeCachedEnv, env.Name) {
				kept = append(kept, v1.EnvVar{Name: env.Name, Value: env.Value})
			}
		}
	}
	return kept
}

// CalicoNodeEnv returns the value of one environment variable on the pod's calico-node container,
// or "" if it isn't set. Only the variables PodTransformer keeps are visible on a cached pod.
func CalicoNodeEnv(pod *v1.Pod, name string) string {
	for _, container := range pod.Spec.Containers {
		if container.Name != calicoNodeContainerName {
			continue
		}
		for _, env := range container.Env {
			if env.Name == name {
				return env.Value
			}
		}
	}
	return ""
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
			p.Spec.Containers = []v1.Container{
				{
					Name: calicoNodeContainerName,
					Env:  keptCalicoNodeEnv(pod),
				},
			}
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
