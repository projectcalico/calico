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
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestBGPConfiguration_Validation(t *testing.T) {
	dur := metav1.Duration{Duration: 120 * time.Second}
	tests := []struct {
		name    string
		obj     client.Object
		wantErr string
	}{
		{
			name: "nodeMeshPassword with mesh disabled is rejected",
			obj: &v3.BGPConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpconfig")},
				Spec: v3.BGPConfigurationSpec{
					NodeToNodeMeshEnabled: ptr.To(false),
					NodeMeshPassword: &v3.BGPPassword{
						SecretKeyRef: nil,
					},
				},
			},
			wantErr: "nodeMeshPassword cannot be set when nodeToNodeMeshEnabled is false",
		},
		{
			name: "nodeMeshMaxRestartTime with mesh disabled is rejected",
			obj: &v3.BGPConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpconfig")},
				Spec: v3.BGPConfigurationSpec{
					NodeToNodeMeshEnabled:  ptr.To(false),
					NodeMeshMaxRestartTime: &dur,
				},
			},
			wantErr: "nodeMeshMaxRestartTime cannot be set when nodeToNodeMeshEnabled is false",
		},
		{
			name: "nodeMeshPassword with mesh enabled is accepted",
			obj: &v3.BGPConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpconfig")},
				Spec: v3.BGPConfigurationSpec{
					NodeToNodeMeshEnabled: ptr.To(true),
					NodeMeshPassword: &v3.BGPPassword{
						SecretKeyRef: nil,
					},
				},
			},
		},
		{
			name: "nodeMeshMaxRestartTime with mesh enabled is accepted",
			obj: &v3.BGPConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpconfig")},
				Spec: v3.BGPConfigurationSpec{
					NodeToNodeMeshEnabled:  ptr.To(true),
					NodeMeshMaxRestartTime: &dur,
				},
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
