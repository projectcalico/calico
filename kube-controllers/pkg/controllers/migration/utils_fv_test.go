// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
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

package migration

import (
	"context"

	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	rtclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// fvHelper bundles the gomega instance and context for FV test assertions.
// Methods use ExpectWithOffset so failures report the caller's line number.
type fvHelper struct {
	g   Gomega
	ctx context.Context
}

// newFVHelper creates an fvHelper for use in a test function.
func newFVHelper(g Gomega, ctx context.Context) *fvHelper {
	return &fvHelper{g: g, ctx: ctx}
}

// getMigration fetches the DatastoreMigration CR by the well-known name.
func (h *fvHelper) getMigration() *DatastoreMigration {
	dm := &DatastoreMigration{}
	h.g.ExpectWithOffset(1, fvRTClient.Get(h.ctx, types.NamespacedName{Name: defaultMigrationName}, dm)).To(Succeed())
	return dm
}

// expectPhase fetches the CR and asserts its phase matches.
func (h *fvHelper) expectPhase(phase DatastoreMigrationPhase) *DatastoreMigration {
	dm := h.getMigration()
	h.g.ExpectWithOffset(1, dm.Status.Phase).To(Equal(phase))
	return dm
}

// getV3Resource fetches a cluster-scoped v3 resource by name.
func (h *fvHelper) getV3Resource(name string, obj rtclient.Object) {
	h.g.ExpectWithOffset(1, fvRTClient.Get(h.ctx, types.NamespacedName{Name: name}, obj)).To(Succeed())
}

// createReadyCalicoNodeDS creates a calico-node DaemonSet with
// CALICO_API_GROUP=projectcalico.org/v3 and a fully-rolled-out status.
func (h *fvHelper) createReadyCalicoNodeDS() {
	installNS := "calico-system"
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: installNS}}
	h.g.ExpectWithOffset(1, rtclient.IgnoreAlreadyExists(fvRTClient.Create(h.ctx, ns))).To(Succeed())

	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "calico-node",
			Namespace:  installNS,
			Generation: 1,
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": "calico-node"}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"k8s-app": "calico-node"}},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "calico-node",
							Image: "calico/node:latest",
							Env: []corev1.EnvVar{
								{Name: "CALICO_API_GROUP", Value: "projectcalico.org/v3"},
							},
						},
					},
				},
			},
		},
	}
	h.g.ExpectWithOffset(1, fvRTClient.Create(h.ctx, ds)).To(Succeed())

	ds.Status = appsv1.DaemonSetStatus{
		ObservedGeneration:     ds.Generation,
		DesiredNumberScheduled: 1,
		CurrentNumberScheduled: 1,
		UpdatedNumberScheduled: 1,
		NumberAvailable:        1,
		NumberReady:            1,
	}
	h.g.ExpectWithOffset(1, fvRTClient.Status().Update(h.ctx, ds)).To(Succeed())
}
