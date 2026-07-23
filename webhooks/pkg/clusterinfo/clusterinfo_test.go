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

package clusterinfo

import (
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/admission/v1"
	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestAdmit(t *testing.T) {
	w := &webhook{namespace: "calico-system"}

	tests := []struct {
		name        string
		username    string
		operation   v1.Operation
		expectAllow bool
	}{
		{
			name:        "calico-node in calico-system can create",
			username:    "system:serviceaccount:calico-system:calico-node",
			operation:   v1.Create,
			expectAllow: true,
		},
		{
			name:        "calico-kube-controllers can update",
			username:    "system:serviceaccount:calico-system:calico-kube-controllers",
			operation:   v1.Update,
			expectAllow: true,
		},
		{
			name:        "calico-node in wrong namespace cannot create",
			username:    "system:serviceaccount:default:calico-node",
			operation:   v1.Create,
			expectAllow: false,
		},
		{
			name:        "regular user cannot create",
			username:    "admin",
			operation:   v1.Create,
			expectAllow: false,
		},
		{
			name:        "regular user cannot update",
			username:    "admin",
			operation:   v1.Update,
			expectAllow: false,
		},
		{
			name:        "regular user cannot delete",
			username:    "admin",
			operation:   v1.Delete,
			expectAllow: false,
		},
		{
			name:        "other service account cannot create",
			username:    "system:serviceaccount:calico-system:my-app",
			operation:   v1.Create,
			expectAllow: false,
		},
		{
			name:        "system:admin cannot create",
			username:    "system:admin",
			operation:   v1.Create,
			expectAllow: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ar := v1.AdmissionReview{
				Request: &v1.AdmissionRequest{
					UID:       "test-uid",
					Operation: tt.operation,
					Name:      "default",
					UserInfo: authv1.UserInfo{
						Username: tt.username,
					},
					Resource: metav1.GroupVersionResource{
						Group:    "projectcalico.org",
						Version:  "v3",
						Resource: "clusterinformations",
					},
				},
			}
			resp := w.admit(ar)
			assert.Equal(t, tt.expectAllow, resp.Allowed, "unexpected admission result for %s", tt.name)
			if !tt.expectAllow {
				assert.Equal(t, metav1.StatusReasonMethodNotAllowed, resp.Result.Reason)
			}
		})
	}
}

func TestIsAllowedUser(t *testing.T) {
	w := &webhook{namespace: "calico-system"}

	tests := []struct {
		username string
		allowed  bool
	}{
		{"system:serviceaccount:calico-system:calico-node", true},
		{"system:serviceaccount:calico-system:calico-kube-controllers", true},
		{"system:serviceaccount:kube-system:calico-node", false},
		{"system:serviceaccount:default:calico-node", false},
		{"system:serviceaccount:calico-system:my-app", false},
		{"admin", false},
		{"system:admin", false},
		{"system:serviceaccount:calico-node", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.username, func(t *testing.T) {
			assert.Equal(t, tt.allowed, w.isAllowedUser(tt.username))
		})
	}
}
