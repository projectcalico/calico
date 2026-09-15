// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package informerutil

import (
	"strings"
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

func TestDeletedObjectPointerType(t *testing.T) {
	pod := &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p1"}}

	tests := []struct {
		name    string
		obj     any
		want    *v1.Pod
		wantErr string
	}{
		{name: "deleted object", obj: pod, want: pod},
		{name: "tombstone", obj: cache.DeletedFinalStateUnknown{Key: "ns/p1", Obj: pod}, want: pod},
		{
			name:    "tombstone wrapping another type",
			obj:     cache.DeletedFinalStateUnknown{Key: "ns/p1", Obj: &v1.Node{}},
			wantErr: `tombstone for key "ns/p1" carried *v1.Node, want *v1.Pod`,
		},
		{
			name:    "unrelated type",
			obj:     &v1.Node{},
			wantErr: "delete event carried *v1.Node, want *v1.Pod or a tombstone",
		},
		{
			name:    "nil",
			obj:     nil,
			wantErr: "delete event carried <nil>, want *v1.Pod or a tombstone",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DeletedObject[*v1.Pod](tc.obj)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("got (%v, nil), want an error containing %q", got, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("got error %q, want it to contain %q", err, tc.wantErr)
				}
				if got != nil {
					t.Fatalf("got object %v alongside the error, want nil", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("got error %q, want nil", err)
			}
			if got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// A tombstone that wraps a nil interface must not be reported as a successful
// unwrap: the zero value of T would look like a real object to the caller.
func TestDeletedObjectTombstoneWrappingNil(t *testing.T) {
	_, err := DeletedObject[*v1.Pod](cache.DeletedFinalStateUnknown{Key: "ns/p1", Obj: nil})
	if err == nil {
		t.Fatal("got nil error, want one")
	}
}

// Handlers that only need object metadata assert to an interface rather than a
// concrete type, so the helper has to work for an interface T too.
func TestDeletedObjectInterfaceType(t *testing.T) {
	pod := &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: "ns"}}

	got, err := DeletedObject[metav1.Object](cache.DeletedFinalStateUnknown{Key: "ns/p1", Obj: pod})
	if err != nil {
		t.Fatalf("got error %q, want nil", err)
	}
	if got.GetName() != "p1" || got.GetNamespace() != "ns" {
		t.Fatalf("got %s/%s, want ns/p1", got.GetNamespace(), got.GetName())
	}

	if _, err := DeletedObject[metav1.Object]("not an object"); err == nil {
		t.Fatal("got nil error for a non-object, want one")
	}
}
