// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package istio

import (
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// LiveWorkloads are the istiod, istio-cni and ztunnel objects in the cluster.
// A nil field means the object does not exist.
type LiveWorkloads struct {
	Istiod  *appsv1.Deployment
	CNI     *appsv1.DaemonSet
	ZTunnel *appsv1.DaemonSet
}

// dataPlaneObjects returns the istio-cni and ztunnel objects to apply.
//
// Istio supports a data plane that is older than istiod, never one that is
// newer. So a new istio-cni or ztunnel image waits until every istiod replica
// runs the new pilot image. A held DaemonSet is left out, which keeps all of
// its live spec until istiod is done.
func (c *IstioComponent) dataPlaneObjects() []client.Object {
	res := c.resources
	live := c.cfg.Live
	if live == nil || istiodRolledOut(live.Istiod, c.IstioPilotImage) {
		return append(append([]client.Object{}, res.CNI...), res.ZTunnel...)
	}

	var objs []client.Object
	objs = append(objs, withoutHeld(res.CNI, res.CNIDaemonSet, live.CNI, istioCNIContainerName)...)
	objs = append(objs, withoutHeld(res.ZTunnel, res.ZTunnelDaemonSet, live.ZTunnel, ztunnelContainerName)...)
	return objs
}

// withoutHeld drops ds from objs when applying it would change the live image.
func withoutHeld(objs []client.Object, ds, live *appsv1.DaemonSet, container string) []client.Object {
	if live == nil || ds == nil || containerImage(&live.Spec.Template.Spec, container) == containerImage(&ds.Spec.Template.Spec, container) {
		return objs
	}
	kept := make([]client.Object, 0, len(objs))
	for _, o := range objs {
		if o != ds {
			kept = append(kept, o)
		}
	}
	return kept
}

// istiodRolledOut reports whether every istiod pod runs image. It counts all
// pods in the status, so pods of the old ReplicaSet that are still running
// keep the rollout open.
func istiodRolledOut(d *appsv1.Deployment, image string) bool {
	if d == nil || containerImage(&d.Spec.Template.Spec, istiodContainerName) != image {
		return false
	}
	want := int32(1)
	if d.Spec.Replicas != nil {
		want = *d.Spec.Replicas
	}
	s := d.Status
	return s.ObservedGeneration >= d.Generation &&
		s.Replicas == want &&
		s.UpdatedReplicas == want &&
		s.AvailableReplicas == want
}

func containerImage(spec *corev1.PodSpec, name string) string {
	for _, c := range spec.Containers {
		if c.Name == name {
			return c.Image
		}
	}
	return ""
}
