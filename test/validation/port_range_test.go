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

package validation_test

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestPortRange_Validation(t *testing.T) {
	obj := func(kind, ns string, spec map[string]any) *unstructured.Unstructured {
		meta := map[string]any{"name": uniqueName("ports")}
		if ns != "" {
			meta["namespace"] = ns
		}
		return &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "projectcalico.org/v3", "kind": kind, "metadata": meta, "spec": spec,
		}}
	}
	rule := func(field string, ports ...any) map[string]any {
		return map[string]any{"ingress": []any{map[string]any{
			"action": "Allow", "protocol": "TCP", "destination": map[string]any{field: ports},
		}}}
	}
	nodePorts := func(ranges ...any) map[string]any {
		return map[string]any{"kubeNodePortRanges": ranges}
	}

	for _, tc := range []struct {
		name string
		obj  *unstructured.Unstructured
	}{
		{"GlobalNetworkPolicy ports", obj("GlobalNetworkPolicy", "", rule("ports", "9000:8000"))},
		{"GlobalNetworkPolicy notPorts", obj("GlobalNetworkPolicy", "", rule("notPorts", "9000:8000"))},
		{"NetworkPolicy ports", obj("NetworkPolicy", "default", rule("ports", "9000:8000"))},
		{"StagedGlobalNetworkPolicy ports", obj("StagedGlobalNetworkPolicy", "", rule("ports", "9000:8000"))},
		{"FelixConfiguration kubeNodePortRanges", obj("FelixConfiguration", "", nodePorts("32767:30000"))},
	} {
		t.Run("rejects descending range in "+tc.name, func(t *testing.T) {
			expectCreateFails(t, tc.obj, "port ranges must be written low:high")
		})
	}

	// Endpoint port names are Kubernetes port names, at most 15 characters, so a longer rule name can never match.
	t.Run("rejects a 16-character named port", func(t *testing.T) {
		expectCreateFails(t, obj("GlobalNetworkPolicy", "", rule("ports", "abcdefghijklmnop")), "15")
	})

	for _, tc := range []struct {
		name string
		obj  *unstructured.Unstructured
	}{
		{"ascending, single, integer and named ports", obj("GlobalNetworkPolicy", "", rule("ports", "8000:9000", "80", 443, "http"))},
		{"a 15-character named port and the widest range", obj("GlobalNetworkPolicy", "", rule("notPorts", "abcdefghijklmno", "00001:65535"))},
		{"the default kubeNodePortRanges", obj("FelixConfiguration", "", nodePorts("30000:32767"))},
	} {
		t.Run("accepts "+tc.name, func(t *testing.T) {
			expectCreateSucceeds(t, tc.obj)
		})
	}
}
