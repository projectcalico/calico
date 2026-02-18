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
	"context"
	"testing"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func tierAction(a v3.Action) *v3.Action { return &a }

func TestTier_Validation(t *testing.T) {
	tests := []struct {
		name    string
		obj     client.Object
		wantErr string
	}{
		{
			name: "kube-admin with Deny is rejected",
			obj: &v3.Tier{
				ObjectMeta: metav1.ObjectMeta{Name: "kube-admin"},
				Spec:       v3.TierSpec{DefaultAction: tierAction(v3.Deny)},
			},
			wantErr: "The 'kube-admin' tier must have default action 'Pass'",
		},
		{
			name: "kube-admin with Pass is accepted",
			obj: &v3.Tier{
				ObjectMeta: metav1.ObjectMeta{Name: "kube-admin"},
				Spec:       v3.TierSpec{DefaultAction: tierAction(v3.Pass)},
			},
		},
		{
			name: "kube-baseline with Deny is rejected",
			obj: &v3.Tier{
				ObjectMeta: metav1.ObjectMeta{Name: "kube-baseline"},
				Spec:       v3.TierSpec{DefaultAction: tierAction(v3.Deny)},
			},
			wantErr: "The 'kube-baseline' tier must have default action 'Pass'",
		},
		{
			name: "kube-baseline with Pass is accepted",
			obj: &v3.Tier{
				ObjectMeta: metav1.ObjectMeta{Name: "kube-baseline"},
				Spec:       v3.TierSpec{DefaultAction: tierAction(v3.Pass)},
			},
		},
		{
			name: "default with Pass is rejected",
			obj: &v3.Tier{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec:       v3.TierSpec{DefaultAction: tierAction(v3.Pass)},
			},
			wantErr: "The 'default' tier must have default action 'Deny'",
		},
		{
			name: "default with Deny is accepted",
			obj: &v3.Tier{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec:       v3.TierSpec{DefaultAction: tierAction(v3.Deny)},
			},
		},
		{
			name: "arbitrary tier without defaultAction defaults to Deny",
			obj: &v3.Tier{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("tier")},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr != "" {
				expectCreateFails(t, tt.obj, tt.wantErr)
			} else {
				expectCreateSucceeds(t, tt.obj)
			}
		})
	}
}

func TestTier_Defaults(t *testing.T) {
	name := uniqueName("tier-dflt")
	tier := &v3.Tier{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	}
	mustCreate(t, tier)

	got := &v3.Tier{}
	if err := testClient.Get(context.Background(), client.ObjectKeyFromObject(tier), got); err != nil {
		t.Fatalf("failed to get tier: %v", err)
	}
	if got.Spec.DefaultAction == nil {
		t.Fatal("expected defaultAction to be defaulted, got nil")
	}
	if *got.Spec.DefaultAction != v3.Deny {
		t.Fatalf("expected defaultAction=Deny, got %q", *got.Spec.DefaultAction)
	}
}
