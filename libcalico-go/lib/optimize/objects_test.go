// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package optimize

import (
	"reflect"
	"testing"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

func newGNP(name string) *apiv3.GlobalNetworkPolicy {
	return &apiv3.GlobalNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       apiv3.KindGlobalNetworkPolicy,
			APIVersion: apiv3.GroupVersionCurrent,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
}

func TestObjects_PassThrough_UnoptimizedSlice(t *testing.T) {
	logutils.ConfigureLoggingForTestingT(t)
	// Use an unhandled type (IPPool) to verify pass-through behavior for a slice.
	ipp1 := &apiv3.IPPool{TypeMeta: metav1.TypeMeta{Kind: apiv3.KindIPPool, APIVersion: apiv3.GroupVersionCurrent}, ObjectMeta: metav1.ObjectMeta{Name: "a"}}
	ipp2 := &apiv3.IPPool{TypeMeta: metav1.TypeMeta{Kind: apiv3.KindIPPool, APIVersion: apiv3.GroupVersionCurrent}, ObjectMeta: metav1.ObjectMeta{Name: "b"}}
	in := []runtime.Object{ipp1, ipp2}

	out := Objects(in)

	if len(out) != 2 {
		t.Fatalf("expected 2 outputs, got %d", len(out))
	}
	if !reflect.DeepEqual(out[0], ipp1) || !reflect.DeepEqual(out[1], ipp2) {
		t.Fatalf("unexpected output slice: %#v", out)
	}
}

func TestObjects_Preserves_GNPList(t *testing.T) {
	logutils.ConfigureLoggingForTestingT(t)
	gnp1 := *newGNP("a")
	gnp1.Spec.Ingress = []apiv3.Rule{{Action: apiv3.Allow}}
	gnp2 := *newGNP("b")
	gnp2.Spec.Egress = []apiv3.Rule{{Action: apiv3.Allow}}
	lst := &apiv3.GlobalNetworkPolicyList{
		TypeMeta: metav1.TypeMeta{
			Kind:       apiv3.KindGlobalNetworkPolicyList,
			APIVersion: apiv3.GroupVersionCurrent,
		},
		Items: []apiv3.GlobalNetworkPolicy{gnp1, gnp2},
	}
	in := []runtime.Object{lst}

	out := Objects(in)

	if len(out) != 1 {
		t.Fatalf("expected 1 output list, got %d", len(out))
	}
	ol, ok := out[0].(*apiv3.GlobalNetworkPolicyList)
	if !ok {
		t.Fatalf("expected GlobalNetworkPolicyList, got %#v", out[0])
	}
	if len(ol.Items) != 2 {
		t.Fatalf("expected 2 items in list, got %d", len(ol.Items))
	}
	if ol.Items[0].Name != "a" || ol.Items[1].Name != "b" {
		t.Fatalf("unexpected list items: %#v", ol.Items)
	}
}

func TestObjects_PassThrough_UnhandledType(t *testing.T) {
	logutils.ConfigureLoggingForTestingT(t)
	ippool := &apiv3.IPPool{
		TypeMeta: metav1.TypeMeta{
			Kind:       apiv3.KindIPPool,
			APIVersion: apiv3.GroupVersionCurrent,
		},
		ObjectMeta: metav1.ObjectMeta{Name: "ippool"},
	}
	out := Objects([]runtime.Object{ippool})
	if len(out) != 1 {
		t.Fatalf("expected 1 output, got %d", len(out))
	}
	if !reflect.DeepEqual(out[0], ippool) {
		t.Fatalf("unexpected output: %#v", out[0])
	}
}

func TestObjects_EmptyInput(t *testing.T) {
	logutils.ConfigureLoggingForTestingT(t)
	out := Objects(nil)
	if len(out) != 0 {
		t.Fatalf("expected empty output for nil input, got %d", len(out))
	}

	out = Objects([]runtime.Object{})
	if len(out) != 0 {
		t.Fatalf("expected empty output for empty slice input, got %d", len(out))
	}
}
