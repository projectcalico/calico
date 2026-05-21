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

func TestNodeFromDeleteObj(t *testing.T) {
	node := &v1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1"}}

	tests := []struct {
		name   string
		obj    any
		want   *v1.Node
		wantOk bool
	}{
		{"direct node", node, node, true},
		{"tombstone with node", cache.DeletedFinalStateUnknown{Key: "n1", Obj: node}, node, true},
		{"tombstone with pod", cache.DeletedFinalStateUnknown{Key: "n1", Obj: &v1.Pod{}}, nil, false},
		{"unrelated type", &v1.Pod{}, nil, false},
		{"nil", nil, nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := nodeFromDeleteObj(tc.obj)
			if ok != tc.wantOk || got != tc.want {
				t.Fatalf("got (%v, %v), want (%v, %v)", got, ok, tc.want, tc.wantOk)
			}
		})
	}
}

func TestPodFromDeleteObj(t *testing.T) {
	pod := &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p1"}}

	tests := []struct {
		name   string
		obj    any
		want   *v1.Pod
		wantOk bool
	}{
		{"direct pod", pod, pod, true},
		{"tombstone with pod", cache.DeletedFinalStateUnknown{Key: "p1", Obj: pod}, pod, true},
		{"tombstone with node", cache.DeletedFinalStateUnknown{Key: "p1", Obj: &v1.Node{}}, nil, false},
		{"unrelated type", &v1.Node{}, nil, false},
		{"nil", nil, nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := podFromDeleteObj(tc.obj)
			if ok != tc.wantOk || got != tc.want {
				t.Fatalf("got (%v, %v), want (%v, %v)", got, ok, tc.want, tc.wantOk)
			}
		})
	}
}
