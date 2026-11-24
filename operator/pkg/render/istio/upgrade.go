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
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// RenderedImageAnnotation records the image the operator rendered for the
// istiod, istio-cni or ztunnel container. The upgrade order compares this,
// not the container image, because an admission webhook may rewrite the
// image on the live spec, for example to pin it by digest.
const RenderedImageAnnotation = "operator.tigera.io/istio-image"

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
	held := map[client.Object]bool{}
	for _, ds := range c.heldDaemonSets() {
		held[ds] = true
	}
	var objs []client.Object
	for _, o := range append(append([]client.Object{}, c.resources.CNI...), c.resources.ZTunnel...) {
		if !held[o] {
			objs = append(objs, o)
		}
	}
	return objs
}

// heldDaemonSets are the rendered DaemonSets whose image change waits for istiod.
func (c *IstioComponent) heldDaemonSets() []*appsv1.DaemonSet {
	res := c.resources
	live := c.cfg.Live
	if live == nil || istiodRolledOut(live.Istiod, c.IstioPilotImage) {
		return nil
	}
	var held []*appsv1.DaemonSet
	if imageChanges(res.CNIDaemonSet, live.CNI) {
		held = append(held, res.CNIDaemonSet)
	}
	if imageChanges(res.ZTunnelDaemonSet, live.ZTunnel) {
		held = append(held, res.ZTunnelDaemonSet)
	}
	return held
}

// DataPlaneHold says which DaemonSets wait for the istiod rollout and where
// that rollout stands. It is empty when nothing waits.
func (c *IstioComponent) DataPlaneHold() string {
	held := c.heldDaemonSets()
	if len(held) == 0 {
		return ""
	}
	names := make([]string, 0, len(held))
	for _, ds := range held {
		names = append(names, ds.Name)
	}
	return fmt.Sprintf("Istio data plane upgrade of DaemonSet %s waits for Deployment %s/%s to roll out: %s",
		strings.Join(names, ", "), IstioNamespace, IstioIstiodDeploymentName, rolloutState(c.cfg.Live.Istiod))
}

func rolloutState(d *appsv1.Deployment) string {
	if d == nil {
		return "it does not exist"
	}
	want := int32(1)
	if d.Spec.Replicas != nil {
		want = *d.Spec.Replicas
	}
	s := d.Status
	return fmt.Sprintf("%d of %d replicas updated, %d available, %d running in total", s.UpdatedReplicas, want, s.AvailableReplicas, s.Replicas)
}

// imageChanges reports whether applying ds would change the live image.
func imageChanges(ds, live *appsv1.DaemonSet) bool {
	return ds != nil && live != nil && renderedImage(live) != renderedImage(ds)
}

// istiodRolledOut reports whether every istiod pod runs image. It counts all
// pods in the status, so pods of the old ReplicaSet that are still running
// keep the rollout open.
func istiodRolledOut(d *appsv1.Deployment, image string) bool {
	if d == nil || renderedImage(d) != image {
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

func renderedImage(o metav1.Object) string {
	return o.GetAnnotations()[RenderedImageAnnotation]
}

func setRenderedImage(o metav1.Object, image string) {
	a := o.GetAnnotations()
	if a == nil {
		a = map[string]string{}
	}
	a[RenderedImageAnnotation] = image
	o.SetAnnotations(a)
}
