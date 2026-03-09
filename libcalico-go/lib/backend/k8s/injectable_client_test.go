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

package k8s

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/kubernetes/scheme"
	fakerest "k8s.io/client-go/rest/fake"

	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// newTestClientOptions builds a ClientOptions with a fake clientset and a fake REST
// client, sufficient for testing core k8s resource operations through the backend.
func newTestClientOptions() (ClientOptions, *fake.Clientset) {
	fakeClientset := fake.NewSimpleClientset()
	fakeREST := &fakerest.RESTClient{
		NegotiatedSerializer: serializer.WithoutConversionCodecFactory{CodecFactory: scheme.Codecs},
		GroupVersion: schema.GroupVersion{
			Group:   "crd.projectcalico.org",
			Version: "v1",
		},
		VersionedAPIPath: "/apis",
	}
	return ClientOptions{
		ClientSet:  fakeClientset,
		RESTClient: fakeREST,
	}, fakeClientset
}

// TestNewWithOptions verifies that a backend client created via NewWithOptions
// with a fake k8s clientset can perform basic CRUD on nodes.
func TestNewWithOptions(t *testing.T) {
	ctx := context.Background()
	opts, fakeClientset := newTestClientOptions()

	c, err := NewWithOptions(opts)
	if err != nil {
		t.Fatalf("NewWithOptions failed: %v", err)
	}
	kc := c.(*KubeClient)

	// Seed a k8s Node through the fake clientset.
	_, err = fakeClientset.CoreV1().Nodes().Create(ctx, &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "test-node",
			Labels: map[string]string{"env": "test"},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to seed node: %v", err)
	}

	// The backend should be able to read it back via its model key.
	kvp, err := kc.Get(ctx, model.ResourceKey{Name: "test-node", Kind: internalapi.KindNode}, "")
	if err != nil {
		t.Fatalf("failed to get node through backend: %v", err)
	}
	node := kvp.Value.(*internalapi.Node)
	if node.Name != "test-node" {
		t.Errorf("expected node name 'test-node', got %q", node.Name)
	}
	if node.Labels["env"] != "test" {
		t.Errorf("expected label env=test, got %v", node.Labels)
	}

	// List should return the node.
	kvps, err := kc.List(ctx, model.ResourceListOptions{Kind: internalapi.KindNode}, "")
	if err != nil {
		t.Fatalf("failed to list nodes: %v", err)
	}
	if len(kvps.KVPairs) != 1 {
		t.Fatalf("expected 1 node, got %d", len(kvps.KVPairs))
	}

	// Seed a second node and verify list returns both.
	_, err = fakeClientset.CoreV1().Nodes().Create(ctx, &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "test-node-2"},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to seed second node: %v", err)
	}
	kvps, err = kc.List(ctx, model.ResourceListOptions{Kind: internalapi.KindNode}, "")
	if err != nil {
		t.Fatalf("failed to list nodes: %v", err)
	}
	if len(kvps.KVPairs) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(kvps.KVPairs))
	}

	// Delete the first node via the fake clientset (node delete isn't supported
	// through the calico backend) and verify the backend reflects the change.
	err = fakeClientset.CoreV1().Nodes().Delete(ctx, "test-node", metav1.DeleteOptions{})
	if err != nil {
		t.Fatalf("failed to delete node: %v", err)
	}
	kvps, err = kc.List(ctx, model.ResourceListOptions{Kind: internalapi.KindNode}, "")
	if err != nil {
		t.Fatalf("failed to list nodes after delete: %v", err)
	}
	if len(kvps.KVPairs) != 1 {
		t.Fatalf("expected 1 node after delete, got %d", len(kvps.KVPairs))
	}
}

// TestNewWithOptions_KubernetesNetworkPolicy verifies that k8s NetworkPolicy CRUD
// works through the injected backend.
func TestNewWithOptions_KubernetesNetworkPolicy(t *testing.T) {
	ctx := context.Background()
	opts, fakeClientset := newTestClientOptions()

	c, err := NewWithOptions(opts)
	if err != nil {
		t.Fatalf("NewWithOptions failed: %v", err)
	}
	kc := c.(*KubeClient)

	// Seed a namespace and network policy.
	_, err = fakeClientset.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to create namespace: %v", err)
	}
	_, err = fakeClientset.NetworkingV1().NetworkPolicies("default").Create(ctx, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to seed network policy: %v", err)
	}

	// List k8s network policies through the backend.
	kvps, err := kc.List(ctx, model.ResourceListOptions{
		Kind:      model.KindKubernetesNetworkPolicy,
		Namespace: "default",
	}, "")
	if err != nil {
		t.Fatalf("failed to list network policies: %v", err)
	}
	if len(kvps.KVPairs) != 1 {
		t.Fatalf("expected 1 network policy, got %d", len(kvps.KVPairs))
	}
}

// TestNewWithOptions_ClientSetExposed verifies that the ClientSet field is the
// same fake we injected.
func TestNewWithOptions_ClientSetExposed(t *testing.T) {
	opts, fakeClientset := newTestClientOptions()

	c, err := NewWithOptions(opts)
	if err != nil {
		t.Fatalf("NewWithOptions failed: %v", err)
	}
	kc := c.(*KubeClient)

	if kc.ClientSet != fakeClientset {
		t.Error("expected ClientSet to be the injected fake")
	}
}

// TestNewWithOptions_RequiredFields verifies that NewWithOptions returns an error
// when required fields are missing.
func TestNewWithOptions_RequiredFields(t *testing.T) {
	_, fakeClientset := newTestClientOptions()

	// Missing both required fields.
	_, err := NewWithOptions(ClientOptions{})
	if err == nil {
		t.Error("expected error when ClientSet is nil")
	}

	// Missing RESTClient.
	_, err = NewWithOptions(ClientOptions{ClientSet: fakeClientset})
	if err == nil {
		t.Error("expected error when RESTClient is nil")
	}
}
