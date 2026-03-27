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

package clientv3

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/kubernetes/scheme"
	fakerest "k8s.io/client-go/rest/fake"

	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

// newTestBackend builds a backend client with a fake clientset and REST client
// for testing the clientv3 injection stack.
func newTestBackend(t *testing.T) (bapi.Client, *fake.Clientset) {
	t.Helper()
	fakeClientset := fake.NewClientset()
	fakeREST := &fakerest.RESTClient{
		NegotiatedSerializer: serializer.WithoutConversionCodecFactory{CodecFactory: scheme.Codecs},
		GroupVersion: schema.GroupVersion{
			Group:   "crd.projectcalico.org",
			Version: "v1",
		},
		VersionedAPIPath: "/apis",
	}
	be, err := k8s.NewWithOptions(k8s.ClientOptions{
		ClientSet:  fakeClientset,
		RESTClient: fakeREST,
	})
	if err != nil {
		t.Fatalf("NewWithOptions failed: %v", err)
	}
	return be, fakeClientset
}

// TestNewFromBackend_NodeList verifies the full injection stack: fake clientset ->
// NewWithOptions backend -> NewFromBackend clientv3 -> Nodes().List().
func TestNewFromBackend_NodeList(t *testing.T) {
	ctx := context.Background()
	be, fakeClientset := newTestBackend(t)
	calicoClient := NewFromBackend(be)

	// Seed nodes through the fake clientset.
	for _, name := range []string{"node-a", "node-b"} {
		_, err := fakeClientset.CoreV1().Nodes().Create(ctx, &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name:   name,
				Labels: map[string]string{"role": "worker"},
			},
		}, metav1.CreateOptions{})
		if err != nil {
			t.Fatalf("failed to seed node %s: %v", name, err)
		}
	}

	// List nodes through the clientv3 API.
	nodes, err := calicoClient.Nodes().List(ctx, options.ListOptions{})
	if err != nil {
		t.Fatalf("failed to list nodes via clientv3: %v", err)
	}
	if len(nodes.Items) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(nodes.Items))
	}

	// Get a specific node.
	node, err := calicoClient.Nodes().Get(ctx, "node-a", options.GetOptions{})
	if err != nil {
		t.Fatalf("failed to get node-a: %v", err)
	}
	if node.Name != "node-a" {
		t.Errorf("expected name 'node-a', got %q", node.Name)
	}
	if node.Labels["role"] != "worker" {
		t.Errorf("expected label role=worker, got %v", node.Labels)
	}
}

// TestNewFromBackend_BackendAccessor verifies that Backend() returns the injected backend.
func TestNewFromBackend_BackendAccessor(t *testing.T) {
	be, _ := newTestBackend(t)
	calicoClient := NewFromBackend(be)

	// The Backend() method isn't on the Interface, but is on the concrete type.
	type backendAccessor interface {
		Backend() bapi.Client
	}
	accessor, ok := calicoClient.(backendAccessor)
	if !ok {
		t.Fatal("clientv3 client does not implement Backend()")
	}
	if accessor.Backend() != be {
		t.Error("Backend() did not return the injected backend")
	}
}
