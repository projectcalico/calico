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

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestHostEndpoint_Validation(t *testing.T) {
	tests := []struct {
		name    string
		obj     client.Object
		wantErr string
	}{
		{
			name: "no interfaceName and no expectedIPs is rejected",
			obj: &v3.HostEndpoint{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("hep")},
				Spec: v3.HostEndpointSpec{
					Node: "mynode",
				},
			},
			wantErr: "at least one of interfaceName or expectedIPs must be specified",
		},
		{
			name: "no node is rejected",
			obj: &v3.HostEndpoint{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("hep")},
				Spec: v3.HostEndpointSpec{
					InterfaceName: "eth0",
				},
			},
			wantErr: "node must be specified",
		},
		{
			name: "interfaceName set is accepted",
			obj: &v3.HostEndpoint{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("hep")},
				Spec: v3.HostEndpointSpec{
					Node:          "mynode",
					InterfaceName: "eth0",
				},
			},
		},
		{
			name: "expectedIPs set is accepted",
			obj: &v3.HostEndpoint{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("hep")},
				Spec: v3.HostEndpointSpec{
					Node:        "mynode",
					ExpectedIPs: []string{"10.0.0.1"},
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
