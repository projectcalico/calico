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

package node

import (
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

func TestOnKubernetesNodeDelete(t *testing.T) {
	node := &v1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1"}}

	// The informer substitutes a cache.DeletedFinalStateUnknown tombstone for
	// the node whenever it loses track of the node's final state. The node
	// still has to reach the label sync, or its labels are never retired.
	tests := []struct {
		name string
		obj  any
		want *v1.Node
	}{
		{name: "deleted node", obj: node, want: node},
		{name: "tombstone wrapping the node", obj: cache.DeletedFinalStateUnknown{Key: "n1", Obj: node}, want: node},
		{name: "tombstone wrapping another type", obj: cache.DeletedFinalStateUnknown{Key: "n1", Obj: &v1.Pod{}}},
		{name: "unrelated type", obj: &v1.Pod{}},
		{name: "nil", obj: nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := &nodeLabelController{k8sNodeUpdate: make(chan *v1.Node, 1)}

			c.OnKubernetesNodeDelete(tc.obj)

			if tc.want == nil {
				if len(c.k8sNodeUpdate) != 0 {
					t.Fatalf("got %d queued updates, want none", len(c.k8sNodeUpdate))
				}
				return
			}
			select {
			case got := <-c.k8sNodeUpdate:
				if got != tc.want {
					t.Fatalf("got node %v, want %v", got, tc.want)
				}
			default:
				t.Fatal("got no queued update, want the deleted node")
			}
		})
	}
}
