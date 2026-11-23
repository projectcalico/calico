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
	"encoding/json"
	"testing"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/admission/v1"
	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
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
			name:        "calico-typha can update",
			username:    "system:serviceaccount:calico-system:calico-typha",
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
		{"system:serviceaccount:calico-system:calico-typha", true},
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

// clusterInfoUpdateCase is one user update to ClusterInformation. edit turns
// the stored object into the one the user submits.
type clusterInfoUpdateCase struct {
	name        string
	edit        func(ci *apiv3.ClusterInformation)
	expectAllow bool
}

// storedClusterInfo returns an unlocked ClusterInformation as Calico writes it.
func storedClusterInfo() *apiv3.ClusterInformation {
	return &apiv3.ClusterInformation{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "default",
			Annotations: map[string]string{"migration.projectcalico.org/migrated-by": "uid-1"},
		},
		Spec: apiv3.ClusterInformationSpec{
			ClusterGUID:    "guid-1",
			ClusterType:    "k8s,kdd",
			CalicoVersion:  "v3.33.1",
			DatastoreReady: ptr.To(true),
		},
	}
}

// rawObject serializes a ClusterInformation the way it arrives in an
// admission request.
func rawObject(t *testing.T, ci *apiv3.ClusterInformation) runtime.RawExtension {
	t.Helper()
	data, err := json.Marshal(ci)
	require.NoError(t, err)
	return runtime.RawExtension{Raw: data}
}

// TestAdmitDatastoreReadyOnly verifies that a user outside the allowlist can
// lock or unlock the datastore, but only when the update changes nothing else.
func TestAdmitDatastoreReadyOnly(t *testing.T) {
	w := &webhook{namespace: "calico-system"}

	cases := []clusterInfoUpdateCase{
		{
			name:        "locking the datastore is allowed",
			edit:        func(ci *apiv3.ClusterInformation) { ci.Spec.DatastoreReady = ptr.To(false) },
			expectAllow: true,
		},
		{
			name: "locking while changing the cluster GUID is denied",
			edit: func(ci *apiv3.ClusterInformation) {
				ci.Spec.DatastoreReady = ptr.To(false)
				ci.Spec.ClusterGUID = "guid-2"
			},
		},
		{
			name: "locking while changing the Calico version is denied",
			edit: func(ci *apiv3.ClusterInformation) {
				ci.Spec.DatastoreReady = ptr.To(false)
				ci.Spec.CalicoVersion = "v9.9.9"
			},
		},
		{
			name: "locking while removing an annotation is denied",
			edit: func(ci *apiv3.ClusterInformation) {
				ci.Spec.DatastoreReady = ptr.To(false)
				ci.Annotations = nil
			},
		},
		{
			name: "locking while adding a label is denied",
			edit: func(ci *apiv3.ClusterInformation) {
				ci.Spec.DatastoreReady = ptr.To(false)
				ci.Labels = map[string]string{"owner": "me"}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Build the update the user submits from the stored object.
			stored := storedClusterInfo()
			submitted := storedClusterInfo()
			tc.edit(submitted)
			ar := v1.AdmissionReview{
				Request: &v1.AdmissionRequest{
					UID:       "test-uid",
					Operation: v1.Update,
					Name:      "default",
					UserInfo:  authv1.UserInfo{Username: "kubernetes-admin"},
					OldObject: rawObject(t, stored),
					Object:    rawObject(t, submitted),
				},
			}

			resp := w.admit(ar)
			assert.Equal(t, tc.expectAllow, resp.Allowed)
			if !tc.expectAllow {
				assert.Equal(t, metav1.StatusReasonMethodNotAllowed, resp.Result.Reason)
			}
		})
	}
}
